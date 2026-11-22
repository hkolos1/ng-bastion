import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { loadConfig } from '@ngbastion/config';
import { scan } from '@ngbastion/core';
import { builtinRules } from '@ngbastion/rules';

const cwd = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../apps/website');

describe('dogfooding: the Angular website scanned by NgBastion', () => {
  it('discovers the Analog workspace and reports no findings at any confidence', async () => {
    const { config } = await loadConfig({ cwd, overrides: { minConfidence: 'low' } });
    const r = await scan({ cwd, config, rules: builtinRules });
    expect(r.projects).toEqual([expect.objectContaining({ name: 'website', kind: 'angular-json' })]);
    expect(r.stats.templatesAnalyzed).toBeGreaterThan(5);
    expect(r.findings.map((f) => `${f.ruleId} ${f.location.file}:${f.location.line}`)).toEqual([]);
    expect(r.diagnostics.filter((d) => d.level !== 'info')).toEqual([]);
  });
});
