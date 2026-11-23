import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { createInterface } from 'node:readline/promises';
import { parseArgs, type ParseArgsConfig } from 'node:util';
import { CONFIDENCES, SEVERITIES, type Confidence, type SecurityRule, type Severity } from '@ngbastion/plugin-api';
import { CONFIG_FILE_NAMES, ConfigError, loadConfig, type ConfigOverrides } from '@ngbastion/config';
import { discoverWorkspace, resolveProjectFiles, scan, SUPPORTED_ANGULAR_MAJORS, type WorkspaceDiagnostic } from '@ngbastion/core';
import { builtinRules } from '@ngbastion/rules';
import { PluginError, loadPlugins } from './plugins.js';
import { renderHtml } from './reporters/html.js';
import { renderJson } from './reporters/json.js';
import { renderSarif } from './reporters/sarif.js';
import { createColors, renderTerminal, type Colors } from './reporters/terminal.js';
import { VERSION } from './version.js';

export const EXIT_OK = 0;
export const EXIT_GATE_FAILED = 1;
export const EXIT_ERROR = 2;

export interface Io {
  stdout: (s: string) => void;
  stderr: (s: string) => void;
  cwd: string;
  isTTY: boolean;
  env: Record<string, string | undefined>;
}

const defaultIo = (): Io => ({
  stdout: (s) => process.stdout.write(s),
  stderr: (s) => process.stderr.write(s),
  cwd: process.cwd(),
  isTTY: Boolean(process.stdout.isTTY),
  env: process.env,
});

export const HELP = `NgBastion ${VERSION} — Angular-aware, local-first security scanner

Usage: ngbastion <command> [options]

Commands:
  scan [dir]        Analyze an Angular workspace (default: current directory)
  init              Create an NgBastion configuration file
  explain <rule>    Show detailed documentation for a rule
  rules             List available security rules
  doctor            Check the environment, workspace and configuration

Global options:
  -h, --help        Show help
  -v, --version     Show version
  --no-color        Disable colors (also: NO_COLOR=1)

Exit codes: 0 success · 1 security gate failed · 2 configuration or execution error
Docs: https://ngbastion.web.app/docs`;

const HELPS: Record<string, string> = {
  scan: `Usage: ngbastion scan [dir] [options]

Options:
  -f, --format <terminal|json|sarif|html>   Output format (default: terminal)
  -o, --output <file>                  Write the report to a file
  --redact-source                      Omit snippets and free-text scan evidence from HTML
  -c, --config <file>                  Config file (default: ngbastion.config.{json,ts,…} in dir)
  --fail-on <severity|none>            Gate threshold: critical|high|medium|low|info|none
  --min-confidence <high|medium|low>   Hide findings below this confidence
  -p, --project <name>                 Angular project to scan (repeatable)
  --show-suppressed                    Also print suppressed findings (terminal)
  -q, --quiet                          Only print the summary
  --verbose                            Print evidence and informational diagnostics`,
  init: `Usage: ngbastion init [dir] [options]

Options:
  --format <json|ts>          Config format (prompted in interactive terminals; default json)
  --preset <name>             recommended | strict | enterprise | payments (default: recommended)
  --force                     Overwrite an existing config file`,
  explain: 'Usage: ngbastion explain <RULE_ID>',
  rules: `Usage: ngbastion rules [options]

Options:
  --category <name>           Filter by category
  --severity <severity>       Filter by default severity
  --json                      Machine-readable output`,
  doctor: 'Usage: ngbastion doctor [dir] [-c <config>]\n\nRead-only checks; never modifies the project.',
};

type Values = Record<string, string | boolean | string[] | undefined>;

function parse(argv: string[], options: ParseArgsConfig['options']): { values: Values; positionals: string[] } {
  return parseArgs({ args: argv, options: { help: { type: 'boolean', short: 'h' }, color: { type: 'boolean' }, 'no-color': { type: 'boolean' }, ...options }, allowPositionals: true, strict: true });
}

function colorsFor(io: Io, values: Record<string, unknown>): Colors {
  const disabled = values['no-color'] === true || values.color === false || io.env.NO_COLOR !== undefined;
  const forced = values.color === true || (io.env.FORCE_COLOR !== undefined && io.env.FORCE_COLOR !== '0');
  return createColors(!disabled && (forced || io.isTTY));
}

function oneOf<T extends string>(name: string, value: unknown, allowed: readonly T[]): T | undefined {
  if (value === undefined) return undefined;
  if (!allowed.includes(value as T)) throw new UsageError(`--${name} must be one of: ${allowed.join(', ')}`);
  return value as T;
}

class UsageError extends Error {}

export async function run(argv: string[], io: Io = defaultIo()): Promise<number> {
  const [command, ...rest] = argv;
  try {
    if (!command || command === '--help' || command === '-h' || command === 'help') {
      io.stdout(`${HELP}\n`);
      return EXIT_OK;
    }
    if (command === '--version' || command === '-v') {
      io.stdout(`${VERSION}\n`);
      return EXIT_OK;
    }
    if (rest.includes('--help') || rest.includes('-h')) {
      if (!HELPS[command]) throw new UsageError(`unknown command '${command}'`);
      io.stdout(`${HELPS[command]}\n`);
      return EXIT_OK;
    }
    switch (command) {
      case 'scan': return await scanCommand(rest, io);
      case 'init': return await initCommand(rest, io);
      case 'explain': return explainCommand(rest, io);
      case 'rules': return rulesCommand(rest, io);
      case 'doctor': return await doctorCommand(rest, io);
      default: throw new UsageError(`unknown command '${command}'. Run 'ngbastion --help'.`);
    }
  } catch (e) {
    if (e instanceof UsageError || e instanceof ConfigError || e instanceof PluginError) {
      io.stderr(`ngbastion: ${e.message}\n`);
      return EXIT_ERROR;
    }
    if (e instanceof TypeError && (e as { code?: string }).code?.startsWith('ERR_PARSE_ARGS')) {
      io.stderr(`ngbastion: ${e.message}\n`);
      return EXIT_ERROR;
    }
    throw e;
  }
}

async function loadRules(pluginSpecs: Parameters<typeof loadPlugins>[0]) {
  const builtinIds = new Set(builtinRules.map((r) => r.meta.id));
  const { rules: pluginRules } = await loadPlugins(pluginSpecs, builtinIds);
  return { rules: [...builtinRules, ...pluginRules] as SecurityRule[], pluginRuleIds: new Set(pluginRules.map((r) => r.meta.id)) };
}

async function scanCommand(argv: string[], io: Io): Promise<number> {
  const { values, positionals } = parse(argv, {
    format: { type: 'string', short: 'f' },
    output: { type: 'string', short: 'o' },
    config: { type: 'string', short: 'c' },
    'fail-on': { type: 'string' },
    'min-confidence': { type: 'string' },
    project: { type: 'string', short: 'p', multiple: true },
    'redact-source': { type: 'boolean' },
    'show-suppressed': { type: 'boolean' },
    quiet: { type: 'boolean', short: 'q' },
    verbose: { type: 'boolean' },
  });
  if (positionals.length > 1) throw new UsageError('scan accepts at most one directory');
  const cwd = path.resolve(io.cwd, positionals[0] ?? '.');
  if (!existsSync(cwd)) throw new UsageError(`directory not found: ${cwd}`);
  const format = oneOf('format', values.format, ['terminal', 'json', 'sarif', 'html'] as const) ?? 'terminal';
  if (format === 'html' && !values.output) throw new UsageError('HTML requires --output <file>, for example --output security-report.html');
  if (values['redact-source'] && format !== 'html') throw new UsageError('--redact-source requires --format html');
  const overrides: ConfigOverrides = {};
  const failOn = oneOf('fail-on', values['fail-on'], [...SEVERITIES, 'none'] as const);
  if (failOn) overrides.failOn = failOn as Severity | 'none';
  const minConf = oneOf('min-confidence', values['min-confidence'], CONFIDENCES);
  if (minConf) overrides.minConfidence = minConf as Confidence;
  if (Array.isArray(values.project) && values.project.length) overrides.projects = values.project;

  const { config, file } = await loadConfig({ cwd, ...(values.config ? { configFile: path.resolve(io.cwd, values.config as string) } : {}), overrides });
  const { rules, pluginRuleIds } = await loadRules(config.plugins);
  const result = await scan({ cwd, config, rules, pluginRuleIds, toolVersion: VERSION });
  const configSources = config.sources.map((s) => (path.isAbsolute(s) ? path.relative(cwd, s) || path.basename(s) : s));
  if (!file) configSources.unshift('(zero-config defaults)');

  const remediation = new Map(rules.map((r) => [r.meta.id, r.meta.docs.remediation]));
  const colors = colorsFor(io, values);
  let report: string;
  if (format === 'json') report = renderJson(result, configSources);
  else if (format === 'html') {
    try {
      report = renderHtml(result, { redactSource: values['redact-source'] === true });
    } catch (error) {
      throw new UsageError(`could not generate HTML report: ${(error as Error).message}`);
    }
  }
  else if (format === 'sarif') report = renderSarif(result);
  else {
    report = renderTerminal(result, {
      colors: values.output ? createColors(false) : colors,
      verbose: values.verbose === true,
      quiet: values.quiet === true,
      showSuppressed: values['show-suppressed'] === true,
      remediation: (id) => remediation.get(id),
    });
  }
  if (values.output) {
    const out = path.resolve(io.cwd, values.output as string);
    try {
      mkdirSync(path.dirname(out), { recursive: true });
      writeFileSync(out, report);
    } catch (error) {
      throw new UsageError(`could not write report to ${out}: ${(error as Error).message}`);
    }
    const summary = `${result.findings.length} finding(s), gate ${result.gate.failOn === 'none' ? 'disabled' : result.gate.failed ? 'FAILED' : 'passed'}`;
    io.stderr(`ngbastion: wrote ${format} report to ${path.relative(io.cwd, out) || out} (${summary})\n`);
  } else {
    io.stdout(report);
  }
  const errors = result.diagnostics.filter((d) => d.level === 'error');
  if (errors.length) {
    if (format !== 'terminal' || values.output) for (const d of errors) io.stderr(`ngbastion: error ${d.code}: ${d.message}\n`);
    return EXIT_ERROR;
  }
  return result.gate.failed ? EXIT_GATE_FAILED : EXIT_OK;
}

async function initCommand(argv: string[], io: Io): Promise<number> {
  const { values, positionals } = parse(argv, {
    format: { type: 'string' },
    preset: { type: 'string' },
    force: { type: 'boolean' },
  });
  const cwd = path.resolve(io.cwd, positionals[0] ?? '.');
  let format = oneOf('format', values.format, ['json', 'ts'] as const);
  const preset = oneOf('preset', values.preset, ['recommended', 'strict', 'enterprise', 'payments'] as const) ?? 'recommended';
  if (!format && io.isTTY) {
    const rl = createInterface({ input: process.stdin, output: process.stdout });
    const answer = (await rl.question('Config format? (json/ts) [json]: ')).trim().toLowerCase();
    rl.close();
    format = answer === 'ts' ? 'ts' : 'json';
  }
  format ??= 'json';
  const existing = CONFIG_FILE_NAMES.map((n) => path.join(cwd, n)).filter((f) => existsSync(f));
  if (existing.length && !values.force) {
    io.stderr(`ngbastion: ${existing.map((f) => path.basename(f)).join(', ')} already exists; re-run with --force to overwrite\n`);
    return EXIT_ERROR;
  }
  const target = path.join(cwd, format === 'ts' ? 'ngbastion.config.ts' : 'ngbastion.config.json');
  const body = {
    extends: [preset],
    rules: {},
    exclude: ['**/*.spec.ts', 'dist/**'],
    failOn: 'high',
  };
  const content = format === 'json'
    ? `${JSON.stringify(body, null, 2)}\n`
    : `import { defineConfig } from 'ngbastion/config';

// Loading a TypeScript config executes it. Keep it free of side effects.
export default defineConfig({
  extends: ['${preset}'],
  rules: {
    // NGB014: 'warn',
  },
  exclude: ['**/*.spec.ts', 'dist/**'],
  failOn: 'high',
});
`;
  for (const f of existing) if (f !== target && values.force) io.stderr(`ngbastion: note: ${path.basename(f)} still exists; remove it to avoid an ambiguous configuration\n`);
  writeFileSync(target, content);
  io.stdout(`Created ${path.relative(io.cwd, target) || target} (preset: ${preset}). Run 'ngbastion scan' next.\n`);
  return EXIT_OK;
}

function findRule(id: string) {
  return builtinRules.find((r) => r.meta.id.toLowerCase() === id.toLowerCase());
}

function explainCommand(argv: string[], io: Io): number {
  const { values, positionals } = parse(argv, {});
  const c = colorsFor(io, values);
  const id = positionals[0];
  if (!id) throw new UsageError('usage: ngbastion explain <RULE_ID>');
  const rule = findRule(id);
  if (!rule) {
    io.stderr(`ngbastion: unknown rule '${id}'. Run 'ngbastion rules' for the list.\n`);
    return EXIT_ERROR;
  }
  const m = rule.meta;
  const d = m.docs;
  const list = (items: string[]) => items.map((i) => `  - ${i}`).join('\n');
  const section = (title: string, body: string) => `${c.bold(title)}\n${body}\n`;
  io.stdout([
    `${c.bold(`${m.id} — ${m.name}`)}`,
    c.dim(`Category: ${m.category} · Default severity: ${m.defaultSeverity}${m.cwe ? ` · ${m.cwe.join(', ')}` : ''}`),
    '',
    section('What it checks', `  ${d.description}`),
    section('Why it matters', `  ${d.rationale}`),
    section('Detected patterns', list(d.patterns)),
    section('Example (unsafe)', d.example.unsafe.split('\n').map((l) => `  ${l}`).join('\n')),
    section('Safer alternative', d.example.safe.split('\n').map((l) => `  ${l}`).join('\n')),
    section('Remediation', `  ${d.remediation}`),
    section('Known limitations', list(d.limitations)),
    section('False-positive considerations', list(d.falsePositives)),
    `${c.bold('Documentation')}: https://ngbastion.web.app/rules/${m.id.toLowerCase()}`,
    '',
  ].join('\n'));
  return EXIT_OK;
}

function rulesCommand(argv: string[], io: Io): number {
  const { values } = parse(argv, { category: { type: 'string' }, severity: { type: 'string' }, json: { type: 'boolean' } });
  const severity = oneOf('severity', values.severity, SEVERITIES);
  const rules = builtinRules.filter((r) => (!values.category || r.meta.category === values.category) && (!severity || r.meta.defaultSeverity === severity));
  if (values.json) {
    io.stdout(`${JSON.stringify(rules.map((r) => ({ id: r.meta.id, name: r.meta.name, category: r.meta.category, severity: r.meta.defaultSeverity, cwe: r.meta.cwe ?? [] })), null, 2)}\n`);
    return EXIT_OK;
  }
  const c = colorsFor(io, values);
  io.stdout(`${c.bold('ID      SEVERITY  CATEGORY          NAME')}\n`);
  for (const r of rules) {
    io.stdout(`${r.meta.id.padEnd(8)}${r.meta.defaultSeverity.padEnd(10)}${r.meta.category.padEnd(18)}${r.meta.name}\n`);
  }
  io.stdout(c.dim(`\n${rules.length} rule(s). Details: ngbastion explain <ID>\n`));
  return EXIT_OK;
}

async function doctorCommand(argv: string[], io: Io): Promise<number> {
  const { values, positionals } = parse(argv, { config: { type: 'string', short: 'c' } });
  const c = colorsFor(io, values);
  const cwd = path.resolve(io.cwd, positionals[0] ?? '.');
  let failed = false;
  const ok = (m: string) => io.stdout(`${c.green('✔')} ${m}\n`);
  const warn = (m: string) => io.stdout(`${c.yellow('!')} ${m}\n`);
  const fail = (m: string) => {
    failed = true;
    io.stdout(`${c.red('✖')} ${m}\n`);
  };

  // Node.js
  const [major, minor] = process.versions.node.split('.').map(Number) as [number, number];
  const nodeOk = (major === 22 && minor >= 22) || (major === 24 && minor >= 15);
  if (nodeOk) ok(`Node.js ${process.versions.node}`);
  else fail(`Node.js ${process.versions.node} is not supported (need 22.22.3+ within 22.x or 24.15.0+ within 24.x)`);

  // Configuration
  let config;
  try {
    const loaded = await loadConfig({ cwd, ...(values.config ? { configFile: path.resolve(io.cwd, values.config as string) } : {}) });
    config = loaded.config;
    ok(loaded.file ? `Configuration ${path.relative(cwd, loaded.file)} is valid (extends: ${config.sources.filter((s) => s.startsWith('preset:')).map((s) => s.slice(7)).join(', ') || 'none'})` : 'No configuration file; zero-config defaults (preset: recommended)');
    for (const d of config.diagnostics) (d.level === 'error' ? fail : warn)(`${d.code}: ${d.message}`);
  } catch (e) {
    fail(`Configuration: ${(e as Error).message}`);
  }

  // Workspace & TypeScript projects
  const ws = discoverWorkspace(cwd);
  if (ws.angularJson) ok(`Angular workspace: angular.json with ${ws.projects.length} project(s): ${ws.projects.map((p) => p.name).join(', ')}`);
  else warn('No angular.json found; NgBastion will analyze tsconfig/TypeScript files directly');
  if (ws.angularVersion) {
    const m = Number.parseInt(ws.angularVersion, 10);
    (SUPPORTED_ANGULAR_MAJORS.includes(m) ? ok : warn)(`Angular ${ws.angularVersion}${SUPPORTED_ANGULAR_MAJORS.includes(m) ? '' : ` (tested: ${SUPPORTED_ANGULAR_MAJORS.join(', ')})`}`);
  } else warn('@angular/core version not detected');
  if (!existsSync(path.join(cwd, 'node_modules'))) warn('node_modules not found: type information for dependencies is unavailable; framework APIs will be identified from import declarations');
  for (const d of ws.diagnostics) (d.level === 'error' ? fail : warn)(`${d.code}: ${d.message}`);
  for (const p of ws.projects) {
    const diags: WorkspaceDiagnostic[] = [];
    const { fileNames } = resolveProjectFiles(p, diags);
    if (fileNames.length) ok(`Project '${p.name}': ${fileNames.length} TypeScript root file(s)${p.tsconfig ? ` from ${path.relative(cwd, p.tsconfig)}` : ''}`);
    else fail(`Project '${p.name}': no TypeScript files found`);
    for (const d of diags) warn(`${d.code}: ${d.message}`);
    if (p.indexHtml) {
      try {
        readFileSync(p.indexHtml, 'utf8');
        ok(`Project '${p.name}': ${path.relative(cwd, p.indexHtml)} readable (used for CSP analysis)`);
      } catch {
        warn(`Project '${p.name}': ${path.relative(cwd, p.indexHtml)} not readable; CSP meta tags cannot be assessed`);
      }
    }
  }

  // Plugins
  if (config?.plugins.length) {
    try {
      const { pluginRuleIds } = await loadRules(config.plugins);
      ok(`Plugins: ${config.plugins.length} loaded (${pluginRuleIds.size} rule(s)); plugins run as trusted code`);
    } catch (e) {
      fail(`Plugins: ${(e as Error).message}`);
    }
  }
  io.stdout(failed ? `\n${c.red('Doctor found problems.')}\n` : `\n${c.green('Environment looks good.')}\n`);
  return failed ? EXIT_ERROR : EXIT_OK;
}
