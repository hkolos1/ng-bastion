// Generates website content from the real NgBastion packages (never hand-copied):
// - rule reference pages from @ngbastion/rules metadata
// - CLI reference from the built CLI's --help output
// - landing demo from a real scan of examples/vulnerable-showcase
// - playground results from real scans of playground-fixtures/*
// - changelog page from the repository CHANGELOG.md
// Requires `pnpm build` at the repository root first (uses packages' dist output).
import { execFileSync } from 'node:child_process';
import { cpSync, existsSync, mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadConfig, resolveConfig, PRESETS } from '@ngbastion/config';
import { scan } from '@ngbastion/core';
import { builtinRules } from '@ngbastion/rules';

const site = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const repo = path.resolve(site, '../..');
const docs = path.join(site, 'src/content/docs');
const generated = path.join(site, 'src/generated');
const fail = (msg) => {
  console.error(`generate: ${msg}`);
  process.exit(1);
};

for (const d of [path.join(docs, 'rules'), generated]) {
  rmSync(d, { recursive: true, force: true });
  mkdirSync(d, { recursive: true });
}

const CATEGORY = {
  'angular-xss': 'Angular security & XSS',
  'cross-window': 'iframe & cross-window communication',
  'navigation-auth': 'Navigation & authentication',
  'sensitive-data': 'Sensitive data & payment security',
  'security-config': 'Security configuration',
  ssr: 'Angular SSR security',
};
const yaml = (s) => JSON.stringify(s);
const list = (items) => (items.length ? items.map((i) => `- ${i}`).join('\n') : '_None documented._');

// ---------------------------------------------------------------- rules
for (const rule of builtinRules) {
  const m = rule.meta;
  const d = m.docs;
  const presets = Object.entries(PRESETS)
    .map(([name, p]) => [name, p.rules?.[m.id]])
    .filter(([, level]) => level)
    .map(([name, level]) => `\`${name}\`: ${level}`)
    .join(', ');
  const body = `---
title: ${yaml(`${m.id}: ${m.name}`)}
description: ${yaml(d.description.split('. ')[0].replace(/`/g, '') + '.')}
---

| | |
|---|---|
| **Rule ID** | \`${m.id}\` |
| **Category** | ${CATEGORY[m.category] ?? m.category} |
| **Default severity** | ${m.defaultSeverity} |
| **CWE** | ${(m.cwe ?? []).map((c) => `[${c}](https://cwe.mitre.org/data/definitions/${c.replace('CWE-', '')}.html)`).join(', ') || 'n/a'} |
| **Built-in presets** | ${presets || 'enabled through extends/presets inheritance'} |

Confidence is reported per finding (high, medium, low) and is independent of severity. See [Reading findings](/docs/getting-started/reading-findings/).

## What it checks

${d.description}

## Why it matters

${d.rationale}

## Detection behavior and supported patterns

${list(d.patterns)}

## Example

\`\`\`ts
${d.example.unsafe}
\`\`\`

## Safer alternative

\`\`\`ts
${d.example.safe}
\`\`\`

## Remediation

${d.remediation}

## False-positive considerations

${list(d.falsePositives)}

## Known limitations

${list(d.limitations)}
${d.references?.length ? `\n## References\n\n${d.references.map((r) => `- [${r.title}](${r.url})`).join('\n')}\n` : ''}
## Run it

\`\`\`sh
ngbastion explain ${m.id}
\`\`\`
`;
  writeFileSync(path.join(docs, 'rules', `${m.id.toLowerCase()}.md`), body);
}

const byCategory = Object.entries(CATEGORY).map(([key, label]) => {
  const rows = builtinRules.filter((r) => r.meta.category === key)
    .map((r) => `| [${r.meta.id}](/rules/${r.meta.id.toLowerCase()}/) | ${r.meta.name} | ${r.meta.defaultSeverity} |`);
  return rows.length ? `## ${label}\n\n| ID | Rule | Default severity |\n|---|---|---|\n${rows.join('\n')}\n` : '';
}).join('\n');
writeFileSync(path.join(docs, 'rules', 'index.md'), `---
title: Security rules
description: The ${builtinRules.length} built-in NgBastion rules for Angular applications, with detection boundaries, examples and remediation.
---

NgBastion ships ${builtinRules.length} built-in rules. Each page documents exactly which patterns the implementation recognizes, its known limitations and its false-positive considerations. A rule that is not listed here is not checked: the absence of findings never proves an application is secure.

${byCategory}
`);

// ---------------------------------------------------------------- CLI reference
const cli = path.join(repo, 'packages/cli/dist/bin.js');
if (!existsSync(cli)) fail('packages/cli/dist/bin.js not found; run `pnpm build` at the repository root first');
const help = (args) => execFileSync(process.execPath, [cli, ...args], { encoding: 'utf8', env: { ...process.env, NO_COLOR: '1' } }).trimEnd();
const commands = [
  ['scan', 'Analyze an Angular workspace. Without a directory argument the current directory is scanned. Angular workspaces are discovered through `angular.json`; otherwise `tsconfig.json`, otherwise every `.ts` file in the directory.'],
  ['init', 'Create a configuration file. In an interactive terminal without `--format` you are asked for the format; in CI it defaults to JSON. Existing configuration is never overwritten without `--force`.'],
  ['explain', 'Print the full documentation of a rule: description, rationale, detected patterns, unsafe and safe examples, remediation, limitations and false-positive considerations.'],
  ['rules', 'List the available rules, optionally filtered.'],
  ['doctor', 'Check Node.js compatibility, configuration validity, Angular workspace detection, TypeScript project resolution, plugin compatibility and file accessibility. Doctor never modifies the project and exits with 2 when it finds a problem.'],
];
writeFileSync(path.join(docs, 'docs', 'cli-reference.md'), `---
title: CLI reference
description: Commands, options and exit codes of the ngbastion command-line interface.
---

:::note[Installation status]
The npm package is not published yet. Until it is, run the CLI from a clone of the repository: \`node packages/cli/dist/bin.js <command>\` (or \`pnpm ngbastion <command>\` from the repository root). The commands below use the intended \`ngbastion\` name.
:::

The help texts on this page are captured from the CLI at build time.

\`\`\`text
${help(['--help'])}
\`\`\`

${commands.map(([c, text]) => `## ngbastion ${c}\n\n${text}\n\n\`\`\`text\n${help([c, '--help'])}\n\`\`\`\n`).join('\n')}
## Exit codes

| Code | Meaning |
|---|---|
| \`0\` | Scan completed and the security gate passed (or \`--fail-on none\`). Other commands: success. |
| \`1\` | Security gate failed: at least one finding from a rule at level \`error\` has a severity at or above \`failOn\`. Findings from \`warn\` rules never fail the gate. |
| \`2\` | Configuration or execution error: invalid options or configuration, unloadable plugin, unknown project, a rule that crashed, or an error-level diagnostic. Treat it as "the scan result cannot be trusted". |

## Examples

\`\`\`sh
ngbastion scan                                  # terminal report, gate on high+
ngbastion scan --format sarif --output results.sarif
ngbastion scan --format json --fail-on critical
ngbastion scan apps/web --project admin --min-confidence low --verbose
ngbastion init --format ts --preset strict
ngbastion explain NGB013
ngbastion rules --category cross-window
\`\`\`

Colors follow the terminal: they are disabled when output is not a TTY, with \`--no-color\` or \`NO_COLOR\`, and forced with \`--color\` or \`FORCE_COLOR\`.
`);

// ---------------------------------------------------------------- showcase demo
const showcase = path.join(repo, 'examples/vulnerable-showcase');
if (!existsSync(path.join(showcase, 'node_modules/@angular/core'))) fail('examples/vulnerable-showcase dependencies are not installed; run `pnpm install` at the repository root');
{
  const { config } = await loadConfig({ cwd: showcase });
  const r = await scan({ cwd: showcase, config, rules: builtinRules });
  const pick = (id, file) => r.findings.find((f) => f.ruleId === id && (!file || f.location.file.includes(file)));
  const featured = [pick('NGB001'), pick('NGB011'), pick('NGB020', 'profile.resolver')].filter(Boolean);
  const summary = {};
  for (const f of r.findings) summary[f.severity] = (summary[f.severity] ?? 0) + 1;
  writeFileSync(path.join(generated, 'showcase.json'), JSON.stringify({
    note: 'Output of `ngbastion scan` (recommended preset) on the repository\'s intentionally vulnerable showcase app, captured at build time.',
    version: r.tool.version,
    files: r.stats.filesAnalyzed,
    templates: r.stats.templatesAnalyzed,
    total: r.findings.length,
    rulesTriggered: new Set(r.findings.map((f) => f.ruleId)).size,
    hidden: r.stats.hiddenBelowConfidence,
    summary,
    gate: r.gate,
    featured: featured.map(({ ruleId, ruleName, severity, confidence, message, location, snippet, trace }) => ({ ruleId, ruleName, severity, confidence, message, location, snippet, trace })),
  }, null, 2));
  if (featured.length < 3) fail('showcase scan did not produce the featured findings (NGB001, NGB011, NGB020)');
}

// ---------------------------------------------------------------- playground
const fixtures = path.join(site, 'playground-fixtures');
const EXAMPLES = {
  'sanitizer-bypass': { title: 'Sanitizer bypass', blurb: 'A query parameter is wrapped in markup and passed to bypassSecurityTrustHtml().' },
  'message-handler': { title: 'iframe message handling', blurb: 'A window message from an embedded payment frame decides where the user is redirected.' },
  'token-storage': { title: 'Sensitive token storage', blurb: 'A login flow stores and logs tokens returned by the API.' },
};
const ruleDocs = Object.fromEntries(builtinRules.map((r) => [r.meta.id, { name: r.meta.name, rationale: r.meta.docs.rationale, remediation: r.meta.docs.remediation }]));
const playground = [];
for (const [id, meta] of Object.entries(EXAMPLES)) {
  const variants = {};
  for (const variant of ['unsafe', 'safe']) {
    const dir = path.join(fixtures, id, variant);
    const files = readdirSync(dir).filter((f) => f.endsWith('.ts'));
    const config = await resolveConfig({ extends: ['recommended'], minConfidence: 'low' }, { cwd: dir });
    const r = await scan({ cwd: dir, config, rules: builtinRules });
    variants[variant] = {
      files: files.map((f) => ({ name: f, code: readFileSync(path.join(dir, f), 'utf8') })),
      findings: r.findings.map(({ ruleId, ruleName, severity, confidence, evidenceKind, message, location, trace }) => ({ ruleId, ruleName, severity, confidence, evidenceKind, message, location, trace })),
    };
  }
  if (!variants.unsafe.findings.length) fail(`playground example ${id}: unsafe variant produced no findings`);
  if (variants.safe.findings.length) fail(`playground example ${id}: safe variant produced findings: ${variants.safe.findings.map((f) => f.ruleId).join(', ')}`);
  playground.push({ id, ...meta, variants });
}
writeFileSync(path.join(generated, 'playground.json'), JSON.stringify({ examples: playground, rules: ruleDocs }, null, 2));

// ---------------------------------------------------------------- changelog
const changelog = path.join(repo, 'CHANGELOG.md');
if (!existsSync(changelog)) fail('CHANGELOG.md not found at the repository root');
const text = readFileSync(changelog, 'utf8').replace(/^# .*\n+/, '');
writeFileSync(path.join(docs, 'changelog.md'), `---\ntitle: Changelog\ndescription: Notable changes to NgBastion, generated from the repository CHANGELOG.md.\n---\n\n${text}`);

// ---------------------------------------------------------------- brand
const brand = path.join(repo, 'assets/brand');
cpSync(brand, path.join(site, 'public/brand'), { recursive: true });
cpSync(path.join(brand, 'favicon.svg'), path.join(site, 'public/favicon.svg'));

console.log(`generate: ${builtinRules.length} rule pages, CLI reference, showcase demo, ${playground.length} playground examples, changelog`);
