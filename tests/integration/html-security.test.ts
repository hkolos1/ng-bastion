import { createHash } from 'node:crypto';
import { resolveConfig } from '@ngbastion/config';
import { scan } from '@ngbastion/core';
import type { SecurityRule } from '@ngbastion/plugin-api';
import { builtinRules } from '@ngbastion/rules';
import { expect, it } from 'vitest';
import { renderHtml } from '../../packages/cli/src/reporters/html.js';

it('preserves redaction across overlapping rules even when the sensitive finding is filtered', async () => {
  const cwd = '/virtual/report-security';
  const secret = 'test-only-value-never-include';
  const marker = '</script><span id="report-injection">';
  const makeRule = (id: string, sensitive: boolean): SecurityRule => ({
    meta: { ...builtinRules[0]!.meta, id, name: marker, category: '__proto__' },
    analyze(ctx) {
      return [{
        node: ctx.sourceFiles[0]!.statements[0]!, redactSnippet: sensitive,
        evidenceKind: 'pattern', confidence: sensitive ? 'low' : 'high',
        message: marker, evidence: ['evidence-only-marker'],
      }];
    },
  });
  const rules = [makeRule('PUBLIC1', false), makeRule('SECRET1', true)];
  const config = await resolveConfig({ rules: { PUBLIC1: 'error', SECRET1: 'error' }, minConfidence: 'high' }, { cwd });
  const result = await scan({ cwd, config, rules, files: { 'src/main.ts': `const value = "${secret}";` } });
  expect(result.ruleCoverage).toEqual({ available: 2, evaluated: ['PUBLIC1', 'SECRET1'] });
  expect(result.stats.hiddenBelowConfidence).toBe(1);
  const before = structuredClone(result);
  const html = renderHtml(result);
  expect(html).not.toContain(secret);
  expect(html).not.toContain(marker);
  expect(html).toContain('&lt;/script&gt;');
  expect(html).toContain('evidence-only-marker');
  expect(renderHtml(result, { redactSource: true })).not.toContain('evidence-only-marker');
  expect(html).not.toContain('unsafe-inline');
  for (const tag of ['script', 'style']) {
    const asset = html.match(new RegExp(`<${tag}>([\\s\\S]*?)</${tag}>`))![1]!;
    expect(html).toContain('sha256-' + createHash('sha256').update(asset).digest('base64'));
  }
  expect(result).toEqual(before);
});
