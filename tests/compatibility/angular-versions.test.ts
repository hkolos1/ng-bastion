import { existsSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { loadConfig } from '@ngbastion/config';
import { scan, type ScanResult } from '@ngbastion/core';
import { builtinRules } from '@ngbastion/rules';

const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');

/** Findings every compatibility fixture must produce (rule → file). */
const EXPECTED = [
  'NGB001 src/app/preview/preview.component.ts',
  'NGB003 src/app/preview/preview.component.ts',
  'NGB007 src/app/messages/bridge.ts',
  'NGB009 src/app/messages/bridge.ts',
  'NGB010 src/app/widgets/embed.component.ts',
  'NGB011 src/app/messages/bridge.ts',
  'NGB012 src/app/messages/bridge.ts',
  'NGB013 src/app/auth/auth.interceptor.ts',
  'NGB014 src/app/auth/token.store.ts',
].sort();

async function scanExample(major: number): Promise<ScanResult> {
  const cwd = path.join(repo, `examples/angular-${major}`);
  const { config } = await loadConfig({ cwd, overrides: { minConfidence: 'low' } });
  return scan({ cwd, config, rules: builtinRules });
}

describe.each([20, 21, 22])('Angular %i compatibility fixture', (major) => {
  const installed = existsSync(path.join(repo, `examples/angular-${major}/node_modules/@angular/core/package.json`));

  it.runIf(installed)('detects the Angular version and resolves framework types through the TypeChecker', async () => {
    const r = await scanExample(major);
    expect(Number.parseInt(r.angularVersion!, 10)).toBe(major);
    const codes = r.diagnostics.map((d) => d.code);
    expect(codes).not.toContain('angular-version-unsupported');
    expect(codes).not.toContain('unresolved-imports');
    expect(codes).not.toContain('template-parse-error');
    expect(codes).not.toContain('parse-error');
    expect(r.projects).toEqual([expect.objectContaining({ name: `angular-${major}`, kind: 'angular-json', templates: 3 })]);
    // No finding relied on name-only sink matching: types were available.
    expect(r.findings.flatMap((f) => f.evidence).join('\n')).not.toContain('receiver type could not be resolved');
  });

  it.runIf(installed)('produces exactly the expected findings and stays silent on the safe equivalents', async () => {
    const r = await scanExample(major);
    expect([...new Set(r.findings.map((f) => `${f.ruleId} ${f.location.file}`))].sort()).toEqual(EXPECTED);
    // Safe patterns in the fixture: sanitized [innerHTML], theme storage, allowlisted message handler,
    // textContent, static sandboxed iframe.
    const lines = r.findings.map((f) => `${f.location.file}:${f.snippet ?? ''}`).join('\n');
    expect(lines).not.toMatch(/theme|textContent|listenSafely|terms\.html/);
    expect(r.findings.find((f) => f.ruleId === 'NGB001')!.trace!.map((s) => s.file)).toContain('src/app/preview/content.service.ts');
    expect(r.findings.find((f) => f.ruleId === 'NGB003')!.trace!.some((s) => s.kind === 'signal')).toBe(true);
  });
});

describe('cross-version consistency', () => {
  it.runIf([20, 21, 22].every((m) => existsSync(path.join(repo, `examples/angular-${m}/node_modules/@angular/core`))))(
    'reports identical rule/location sets for identical code on Angular 20, 21 and 22',
    async () => {
      const keys = await Promise.all([20, 21, 22].map(async (m) => (await scanExample(m)).findings.map((f) => `${f.ruleId}:${f.location.file}:${f.location.line}:${f.confidence}`).sort()));
      expect(keys[1]).toEqual(keys[0]);
      expect(keys[2]).toEqual(keys[0]);
    },
  );
});
