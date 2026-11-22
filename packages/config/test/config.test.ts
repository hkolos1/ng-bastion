import { mkdtempSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { BUILTIN_RULE_IDS, ConfigError, PRESETS, loadConfig, resolveConfig, validateConfig } from '../src/index.js';

describe('validateConfig', () => {
  it('accepts a complete valid config', () => {
    expect(validateConfig({
      extends: ['recommended'],
      rules: { NGB001: 'error', NGB002: { level: 'warn', severity: 'medium', options: { x: 1 } } },
      include: ['src/**'], exclude: ['dist/**'], projects: ['app'], failOn: 'none', minConfidence: 'low',
      limits: { maxDepth: 10 }, trustedSanitizers: ['clean'], plugins: ['./p.mjs'],
      exceptions: [{ rule: 'NGB003', files: ['src/a.ts'], justification: 'reviewed by security team', expires: '2030-01-01', line: 3, fingerprint: 'abc' }],
      policy: { name: 'acme', mandatoryRules: ['NGB001'], maxFailOn: 'high', allowInlineSuppressions: false, requireExceptionExpiry: true, maxExceptionDays: 30 },
    })).toEqual([]);
  });

  it('reports every invalid property with its path', () => {
    const errors = validateConfig({
      bogus: 1, extends: 'recommended', rules: { bad: 'error', NGB001: 'loud', NGB002: { level: 'x', severity: 'y', options: 1, extra: true }, NGB003: 7 },
      failOn: 'sometimes', minConfidence: 'certain', limits: { maxDepth: -1, nope: 1 },
      exceptions: [{ rule: '', justification: 'short', expires: '2030-02-30', line: 0, fingerprint: 1, other: 1 }, 'x'],
      policy: { mandatoryRules: [1], maxFailOn: 'x', allowInlineSuppressions: 'no', maxExceptionDays: 0, unknown: 1, name: 3 },
    });
    for (const p of ['bogus', 'extends', 'rules.bad', 'rules.NGB001', 'rules.NGB002.level', 'rules.NGB002.severity', 'rules.NGB002.options', 'rules.NGB002.extra', 'rules.NGB003',
      'failOn', 'minConfidence', 'limits.maxDepth', 'limits.nope', 'exceptions[0].rule', 'exceptions[0].files', 'exceptions[0].justification', 'exceptions[0].expires',
      'exceptions[0].line', 'exceptions[0].fingerprint', 'exceptions[0].other', 'exceptions[1]', 'policy.mandatoryRules', 'policy.maxFailOn',
      'policy.allowInlineSuppressions', 'policy.maxExceptionDays', 'policy.unknown', 'policy.name']) {
      expect(errors.some((e) => e.startsWith(`${p}:`)), p).toBe(true);
    }
    expect(validateConfig(null)).toEqual(['config: expected an object']);
    expect(validateConfig({ rules: [], limits: [], exceptions: {}, policy: [] }).length).toBe(4);
  });
});

describe('resolveConfig', () => {
  it('defaults to the recommended preset with documented rule selection', async () => {
    const c = await resolveConfig({}, { cwd: '/x' });
    expect(Object.keys(c.rules).sort()).toEqual([...BUILTIN_RULE_IDS].sort());
    expect(c.rules.NGB008!.level).toBe('warn');
    expect(c.failOn).toBe('high');
    expect(c.minConfidence).toBe('medium');
    expect(c.exclude).toContain('**/*.spec.ts');
  });

  it('applies precedence: presets < config < overrides < policy', async () => {
    const c = await resolveConfig(
      { extends: ['strict'], rules: { NGB001: 'off', NGB002: { severity: 'low' } }, failOn: 'low', policy: { mandatoryRules: ['NGB001'], maxFailOn: 'medium' } },
      { cwd: '/x', overrides: { failOn: 'critical', minConfidence: 'high', projects: ['web'] } },
    );
    expect(c.rules.NGB001!.level).toBe('error');
    expect(c.rules.NGB002).toEqual({ level: 'error', severity: 'low', options: {} });
    expect(c.failOn).toBe('medium');
    expect(c.minConfidence).toBe('high');
    expect(c.projects).toEqual(['web']);
    expect(c.diagnostics.map((d) => d.code)).toEqual(['policy-violation', 'policy-violation']);
  });

  it('enterprise and payments presets carry governance policies', async () => {
    const e = await resolveConfig({ extends: ['enterprise'] }, { cwd: '/x' });
    expect(e.policy.allowInlineSuppressions).toBe(false);
    expect(e.policy.requireExceptionExpiry).toBe(true);
    expect(e.policy.mandatoryRules.has('NGB015')).toBe(true);
    const p = await resolveConfig({ extends: ['payments'] }, { cwd: '/x' });
    expect(p.minConfidence).toBe('low');
    expect(p.policy.mandatoryRules.get('NGB016')).toBe('ngbastion:payments');
    expect(Object.keys(PRESETS)).toEqual(['recommended', 'strict', 'enterprise', 'payments']);
  });

  it('validates exceptions against policy limits', async () => {
    const c = await resolveConfig({
      policy: { requireExceptionExpiry: true, maxExceptionDays: 30 },
      exceptions: [
        { rule: 'NGB001', files: ['a.ts'], justification: 'no expiry given here' },
        { rule: 'NGB001', files: ['a.ts'], justification: 'too far in the future', expires: '2099-01-01' },
        { rule: 'NGB001', files: ['a.ts'], justification: 'within the allowed window', expires: '2026-12-01' },
      ],
    }, { cwd: '/x', now: new Date('2026-11-22T00:00:00Z') });
    expect(c.exceptions).toHaveLength(1);
    expect(c.diagnostics.filter((d) => d.code === 'exception-invalid')).toHaveLength(2);
  });

  it('resolves shared configs from files and installed packages, detecting cycles', async () => {
    const dir = mkdtempSync(path.join(os.tmpdir(), 'ngb-cfg-'));
    writeFileSync(path.join(dir, 'a.json'), JSON.stringify({ extends: ['./b.json'], exclude: ['gen/**'] }));
    writeFileSync(path.join(dir, 'b.json'), JSON.stringify({ rules: { NGB010: 'off' }, plugins: ['./p.mjs'] }));
    writeFileSync(path.join(dir, 'loop1.json'), JSON.stringify({ extends: ['./loop2.json'] }));
    writeFileSync(path.join(dir, 'loop2.json'), JSON.stringify({ extends: ['./loop1.json'] }));
    const c = await resolveConfig({ extends: ['recommended', './a.json'] }, { cwd: dir, file: path.join(dir, 'ngbastion.config.json') });
    expect(c.rules.NGB010!.level).toBe('off');
    expect(c.exclude).toContain('gen/**');
    expect(c.plugins).toEqual([{ specifier: './p.mjs', from: dir }]);
    await expect(resolveConfig({ extends: ['./loop1.json'] }, { cwd: dir, file: path.join(dir, 'x.json') })).rejects.toThrow(/circular/);
    await expect(resolveConfig({ extends: ['@acme/not-installed'] }, { cwd: dir })).rejects.toThrow(ConfigError);
    await expect(resolveConfig({ extends: ['./missing.json'] }, { cwd: dir })).rejects.toThrow(/not found/);
  });

  it('loadConfig reports missing explicit files and zero-config defaults', async () => {
    const dir = mkdtempSync(path.join(os.tmpdir(), 'ngb-cfg-'));
    expect((await loadConfig({ cwd: dir })).file).toBeUndefined();
    await expect(loadConfig({ cwd: dir, configFile: 'nope.json' })).rejects.toThrow(/config file not found/);
    writeFileSync(path.join(dir, 'ngbastion.config.mjs'), 'export const notDefault = 1;');
    await expect(loadConfig({ cwd: dir })).rejects.toThrow(/no default export/);
  });
});
