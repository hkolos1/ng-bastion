import { existsSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { loadConfig } from '@ngbastion/config';
import { scan } from '@ngbastion/core';
import { builtinRules } from '@ngbastion/rules';

const cwd = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../examples/vulnerable-showcase');

describe('vulnerable showcase (typed mode, Angular 22)', () => {
  it.runIf(existsSync(path.join(cwd, 'node_modules/@angular/common')))('demonstrates every built-in rule with no unsupported HttpClient flows', async () => {
    const { config } = await loadConfig({ cwd, overrides: { minConfidence: 'low' } });
    const r = await scan({ cwd, config, rules: builtinRules });
    const ids = new Set(r.findings.map((f) => f.ruleId));
    expect([...ids].sort()).toEqual(builtinRules.map((x) => x.meta.id));
    // HttpClient resolves through the TypeChecker (package @angular/common, entry point @angular/common/http).
    expect(r.diagnostics.find((d) => d.code === 'unsupported-construct')?.message ?? '').not.toMatch(/post\(\)|get\(\)/);
    const transfer = r.findings.find((f) => f.ruleId === 'NGB020' && f.location.file.endsWith('profile.resolver.ts'))!;
    expect(transfer.trace?.[0]?.description).toMatch(/HttpClient\.get\('\/api\/me'\)/);
    // Safe counterpart in the same file is not reported.
    expect(r.findings.some((f) => f.ruleId === 'NGB015' && f.snippet?.includes('paymentMethodId'))).toBe(false);
  });
});
