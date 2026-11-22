import { execFileSync, spawnSync } from 'node:child_process';
import { cpSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import Ajv from 'ajv';
import addFormats from 'ajv-formats';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { run, type Io } from '../../packages/cli/src/run.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const repo = path.resolve(here, '../..');
const fixture = path.join(repo, 'tests/fixtures/cli-app');
const tmpRoot = path.join(repo, 'tests/.tmp');

async function cli(args: string[], cwd = repo) {
  let stdout = '';
  let stderr = '';
  const io: Io = { stdout: (s) => { stdout += s; }, stderr: (s) => { stderr += s; }, cwd, isTTY: false, env: {} };
  const code = await run(args, io);
  return { code, stdout, stderr };
}

/** Copy of the fixture app inside the repo (so `ngbastion/config` resolves) with an optional config. */
function workspace(files: Record<string, string> = {}): string {
  const dir = mkdtempSync(path.join(tmpRoot, 'ws-'));
  cpSync(fixture, dir, { recursive: true });
  for (const [name, content] of Object.entries(files)) writeFileSync(path.join(dir, name), content);
  return dir;
}

beforeAll(() => {
  rmSync(tmpRoot, { recursive: true, force: true });
  execFileSync('mkdir', ['-p', tmpRoot]);
});
afterAll(() => rmSync(tmpRoot, { recursive: true, force: true }));

describe('cli basics', () => {
  it('prints help and version', async () => {
    expect((await cli(['--help'])).stdout).toContain('Commands:');
    expect((await cli(['--version'])).stdout.trim()).toBe('0.1.0');
    expect((await cli(['scan', '--help'])).stdout).toContain('--fail-on');
  });

  it('rejects unknown commands and options with exit code 2', async () => {
    expect((await cli(['frobnicate'])).code).toBe(2);
    const r = await cli(['scan', fixture, '--bogus']);
    expect(r.code).toBe(2);
    expect(r.stderr).toMatch(/bogus/);
    expect((await cli(['scan', fixture, '--format', 'html'])).code).toBe(2);
  });

  it('lists and explains rules', async () => {
    const list = JSON.parse((await cli(['rules', '--json'])).stdout) as { id: string }[];
    expect(list.map((r) => r.id)).toEqual(Array.from({ length: list.length }, (_, i) => `NGB${String(i + 1).padStart(3, '0')}`));
    const explain = await cli(['explain', 'ngb003']);
    for (const s of ['What it checks', 'Why it matters', 'Detected patterns', 'Example (unsafe)', 'Safer alternative', 'Remediation', 'Known limitations', 'https://ngbastion.dev/rules/ngb003']) {
      expect(explain.stdout).toContain(s);
    }
    expect((await cli(['explain', 'NGB999'])).code).toBe(2);
  });
});

describe('scan: gate, formats and output', () => {
  it('fails the gate (exit 1) on high findings and passes with --fail-on critical when only highs remain', async () => {
    const ws = workspace({ 'ngbastion.config.json': JSON.stringify({ rules: { NGB004: 'off' } }) });
    const failing = await cli(['scan', ws]);
    expect(failing.code).toBe(1);
    expect(failing.stdout).toMatch(/Security gate \(fail on high\+\): FAILED/);
    expect((await cli(['scan', ws, '--fail-on', 'critical'])).code).toBe(0);
    expect((await cli(['scan', ws, '--fail-on', 'none'])).code).toBe(0);
  });

  it('treats warn-level rules as non-blocking', async () => {
    const ws = workspace({ 'ngbastion.config.json': JSON.stringify({ rules: { NGB003: 'warn', NGB004: 'warn' } }) });
    const r = await cli(['scan', ws, '--format', 'json']);
    expect(r.code).toBe(0);
    expect(JSON.parse(r.stdout).findings.every((f: { level: string }) => f.level === 'warn')).toBe(true);
  });

  it('emits JSON that validates against the published schema and contains no absolute paths', async () => {
    const r = await cli(['scan', fixture, '--format', 'json']);
    const report = JSON.parse(r.stdout);
    const ajv = new Ajv({ allErrors: true, strict: false });
    addFormats(ajv);
    const schema = JSON.parse(readFileSync(path.join(repo, 'packages/cli/schema/report-v1.json'), 'utf8'));
    const valid = ajv.validate(schema, report);
    expect(ajv.errors ?? []).toEqual([]);
    expect(valid).toBe(true);
    expect(r.stdout).not.toContain(repo);
    expect(report.findings[0].trace[0].kind).toBe('source');
    expect(report.summary.gate.failed).toBe(true);
  });

  it('emits valid SARIF 2.1.0 with code flows, fingerprints and suppressions', async () => {
    const r = await cli(['scan', fixture, '--format', 'sarif']);
    const sarif = JSON.parse(r.stdout);
    const ajv = new Ajv({ allErrors: true, strict: false, validateSchema: false });
    addFormats(ajv);
    const schema = JSON.parse(readFileSync(path.join(repo, 'tests/fixtures/schemas/sarif-2.1.0.json'), 'utf8'));
    const valid = ajv.validate(schema, sarif);
    expect(ajv.errors ?? []).toEqual([]);
    expect(valid).toBe(true);
    const results = sarif.runs[0].results;
    const flow = results.find((x: { ruleId: string }) => x.ruleId === 'NGB004');
    expect(flow.codeFlows[0].threadFlows[0].locations.length).toBeGreaterThan(1);
    expect(flow.partialFingerprints['ngbastion/v1']).toMatch(/^[0-9a-f]{20}$/);
    expect(results.some((x: { suppressions?: unknown[] }) => x.suppressions?.length)).toBe(true);
    const rule = sarif.runs[0].tool.driver.rules.find((x: { id: string }) => x.id === 'NGB004');
    expect(rule.properties['security-severity']).toBe('9.5');
    expect(r.stdout).not.toContain(repo);
  });

  it('writes reports to --output and keeps fingerprints stable across runs', async () => {
    const out = path.join(tmpRoot, 'nested/report.sarif');
    const r = await cli(['scan', fixture, '--format', 'sarif', '--output', out]);
    expect(r.code).toBe(1);
    expect(r.stderr).toContain('wrote sarif report');
    expect(existsSync(out)).toBe(true);
    const a = JSON.parse((await cli(['scan', fixture, '--format', 'json'])).stdout).findings.map((f: { fingerprint: string }) => f.fingerprint);
    const b = JSON.parse((await cli(['scan', fixture, '--format', 'json'])).stdout).findings.map((f: { fingerprint: string }) => f.fingerprint);
    expect(a).toEqual(b);
  });

  it('honours inline suppressions only with a justification', async () => {
    const report = JSON.parse((await cli(['scan', fixture, '--format', 'json'])).stdout);
    expect(report.suppressed).toHaveLength(1);
    expect(report.suppressed[0].suppression.justification).toContain('SEC-142');
    expect(report.diagnostics.some((d: { code: string }) => d.code === 'suppression-invalid')).toBe(true);
  });
});

describe('configuration', () => {
  it('reports invalid configuration with exit code 2 and the property path', async () => {
    const ws = workspace({ 'ngbastion.config.json': JSON.stringify({ rules: { NGB001: 'loud' }, failOn: 'sometimes' }) });
    const r = await cli(['scan', ws]);
    expect(r.code).toBe(2);
    expect(r.stderr).toContain('rules.NGB001');
    expect(r.stderr).toContain('failOn');
  });

  it('rejects malformed JSON and ambiguous config files', async () => {
    expect((await cli(['scan', workspace({ 'ngbastion.config.json': '{ nope' })])).stderr).toContain('invalid JSON');
    const r = await cli(['scan', workspace({ 'ngbastion.config.json': '{}', 'ngbastion.config.ts': 'export default {}' })]);
    expect(r.code).toBe(2);
    expect(r.stderr).toContain('multiple config files');
  });

  it('loads TypeScript configs with defineConfig from ngbastion/config', async () => {
    const ws = workspace({
      'ngbastion.config.ts': `import { defineConfig } from 'ngbastion/config';\nexport default defineConfig({ extends: ['recommended'], rules: { NGB004: 'off' }, failOn: 'critical' });\n`,
    });
    const r = await cli(['scan', ws, '--format', 'json']);
    const report = JSON.parse(r.stdout);
    expect(report.findings.some((f: { ruleId: string }) => f.ruleId === 'NGB004')).toBe(false);
    expect(report.scan.config.failOn).toBe('critical');
    expect(report.scan.config.sources).toContain('ngbastion.config.ts');
    expect(r.code).toBe(0);
  });

  it('enforces organizational policies from shared configs', async () => {
    const ws = workspace({
      'org-policy.json': JSON.stringify({ policy: { name: 'acme', mandatoryRules: ['NGB003'], maxFailOn: 'high' } }),
      'ngbastion.config.json': JSON.stringify({ extends: ['recommended', './org-policy.json'], rules: { NGB003: 'off' }, failOn: 'none' }),
    });
    const r = await cli(['scan', ws, '--format', 'json']);
    const report = JSON.parse(r.stdout);
    expect(report.findings.some((f: { ruleId: string }) => f.ruleId === 'NGB003')).toBe(true);
    expect(report.scan.config.failOn).toBe('high');
    const messages = report.diagnostics.map((d: { message: string }) => d.message).join('\n');
    expect(messages).toMatch(/NGB003 is mandatory under policy 'acme'/);
    expect(messages).toMatch(/failOn 'none' is looser than the policy maximum 'high'/);
    expect(r.code).toBe(1);
  });

  it('applies scoped exceptions, re-reports expired ones and rejects workspace-wide globs', async () => {
    const ws = workspace({
      'ngbastion.config.json': JSON.stringify({
        exceptions: [
          { rule: 'NGB004', files: ['src/app/view.ts'], justification: 'calculator accepts only internal expressions (SEC-1)' },
          { rule: 'NGB003', files: ['src/app/view.ts'], justification: 'expired waiver for banner rendering', expires: '2020-01-01' },
          { rule: 'NGB003', files: ['**'], justification: 'attempt to silence everything at once' },
        ],
      }),
    });
    const report = JSON.parse((await cli(['scan', ws, '--format', 'json'])).stdout);
    expect(report.suppressed.map((f: { ruleId: string }) => f.ruleId)).toContain('NGB004');
    expect(report.findings.some((f: { ruleId: string; location: { file: string } }) => f.ruleId === 'NGB003' && f.location.file === 'src/app/view.ts')).toBe(true);
    const codes = report.diagnostics.map((d: { code: string }) => d.code);
    expect(codes).toContain('exception-expired');
    expect(codes).toContain('exception-invalid');
  });

  it('disallows inline suppressions under a policy that forbids them', async () => {
    const ws = workspace({ 'ngbastion.config.json': JSON.stringify({ extends: ['enterprise'] }) });
    const report = JSON.parse((await cli(['scan', ws, '--format', 'json'])).stdout);
    expect(report.suppressed).toHaveLength(0);
    expect(report.diagnostics.some((d: { code: string }) => d.code === 'suppression-disallowed')).toBe(true);
  });

  it('refuses remote extends and unknown projects', async () => {
    const ws = workspace({ 'ngbastion.config.json': JSON.stringify({ extends: ['https://evil.example/config.json'] }) });
    expect((await cli(['scan', ws])).stderr).toContain('remote configuration');
    expect((await cli(['scan', fixture, '--project', 'nope'])).code).toBe(2);
  });
});

describe('plugins', () => {
  const plugin = (apiVersion: number, id = 'ACME001') => `export default {
  apiVersion: ${apiVersion},
  name: 'acme-rules',
  rules: [{
    meta: { id: '${id}', name: 'No document.domain writes', category: 'custom', defaultSeverity: 'medium',
      docs: { description: 'Flags document.domain assignments.', rationale: 'Relaxes same-origin policy.', patterns: [], limitations: [], falsePositives: [], remediation: 'Remove it.', example: { unsafe: '', safe: '' } } },
    analyze(ctx) {
      return ctx.index.assignments
        .filter((a) => a.left.getText() === 'document.domain')
        .map((a) => ({ node: a, message: 'document.domain is assigned', confidence: 'high', evidenceKind: 'pattern' }));
    },
  }],
};
`;

  it('registers trusted custom rules from a local plugin', async () => {
    const ws = workspace({ 'acme-plugin.mjs': plugin(1), 'ngbastion.config.json': JSON.stringify({ plugins: ['./acme-plugin.mjs'] }) });
    writeFileSync(path.join(ws, 'src/app/domain.ts'), "document.domain = 'example.com';\n");
    const report = JSON.parse((await cli(['scan', ws, '--format', 'json'])).stdout);
    const f = report.findings.find((x: { ruleId: string }) => x.ruleId === 'ACME001');
    expect(f.severity).toBe('medium');
    expect(f.location.file).toBe('src/app/domain.ts');
  });

  it('rejects incompatible API versions and reserved rule ids', async () => {
    const bad = workspace({ 'p.mjs': plugin(99), 'ngbastion.config.json': JSON.stringify({ plugins: ['./p.mjs'] }) });
    const r = await cli(['scan', bad]);
    expect(r.code).toBe(2);
    expect(r.stderr).toMatch(/apiVersion 99 is not compatible/);
    const reserved = workspace({ 'p.mjs': plugin(1, 'NGB777'), 'ngbastion.config.json': JSON.stringify({ plugins: ['./p.mjs'] }) });
    expect((await cli(['scan', reserved])).stderr).toMatch(/NGB prefix is reserved/);
  });
});

describe('init and doctor', () => {
  it('creates JSON and TS configs and refuses to overwrite without --force', async () => {
    const dir = mkdtempSync(path.join(tmpRoot, 'init-'));
    expect((await cli(['init', dir])).code).toBe(0);
    expect(JSON.parse(readFileSync(path.join(dir, 'ngbastion.config.json'), 'utf8')).extends).toEqual(['recommended']);
    const again = await cli(['init', dir, '--format', 'ts']);
    expect(again.code).toBe(2);
    expect(again.stderr).toContain('already exists');
    rmSync(path.join(dir, 'ngbastion.config.json'));
    expect((await cli(['init', dir, '--format', 'ts', '--preset', 'strict'])).code).toBe(0);
    expect(readFileSync(path.join(dir, 'ngbastion.config.ts'), 'utf8')).toContain("extends: ['strict']");
  });

  it('doctor reports environment status without modifying the project', async () => {
    const ws = workspace();
    const before = readFileSync(path.join(ws, 'tsconfig.json'), 'utf8');
    const r = await cli(['doctor', ws]);
    expect(r.stdout).toContain('Node.js');
    expect(r.stdout).toMatch(/Project '.*': 2 TypeScript root file/);
    expect(readFileSync(path.join(ws, 'tsconfig.json'), 'utf8')).toBe(before);
    expect(existsSync(path.join(ws, 'ngbastion.config.json'))).toBe(false);
    const broken = await cli(['doctor', workspace({ 'ngbastion.config.json': '{"failOn": 1}' })]);
    expect(broken.code).toBe(2);
    expect(broken.stdout).toContain('Configuration:');
  });
});

describe('built binary (end-to-end)', () => {
  const bin = path.join(repo, 'packages/cli/dist/bin.js');
  it.runIf(existsSync(bin))('runs as a separate process with predictable exit codes', () => {
    const ok = spawnSync(process.execPath, [bin, '--version'], { encoding: 'utf8' });
    expect(ok.status).toBe(0);
    const gate = spawnSync(process.execPath, [bin, 'scan', fixture, '--format', 'json'], { encoding: 'utf8', env: { ...process.env, NO_COLOR: '1' } });
    expect(gate.status).toBe(1);
    expect(JSON.parse(gate.stdout).tool.name).toBe('NgBastion');
    const err = spawnSync(process.execPath, [bin, 'scan', path.join(os.tmpdir(), 'does-not-exist-ngb')], { encoding: 'utf8' });
    expect(err.status).toBe(2);
  });
});
