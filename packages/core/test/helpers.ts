import { resolveConfig } from '@ngbastion/config';
import { defineRule, type AnalysisContext, type RuleFinding, type SecurityRule } from '@ngbastion/plugin-api';
import { scan, type ScanResult } from '../src/index.js';

export const ROOT = '/virtual/app';

/** Runs `analyze` against in-memory files and returns the scan result. */
export async function runProbe(files: Record<string, string>, analyze: (ctx: AnalysisContext) => RuleFinding[]): Promise<ScanResult> {
  const rule: SecurityRule = defineRule({
    meta: { id: 'TEST001', name: 'probe', category: 'test', defaultSeverity: 'high', docs: { description: '', rationale: '', patterns: [], limitations: [], falsePositives: [], remediation: '', example: { unsafe: '', safe: '' } } },
    analyze,
  });
  const config = await resolveConfig({ extends: [], rules: { TEST001: 'error' }, minConfidence: 'low' }, { cwd: ROOT });
  return scan({ cwd: ROOT, config, rules: [rule], files });
}

/** Traces the first argument of every call to `sink(...)`. */
export async function traceSink(files: Record<string, string>, context: 'html' | 'url' | 'generic' = 'html') {
  const out: ReturnType<AnalysisContext['taint']['trace']>[] = [];
  await runProbe(files, (ctx) => {
    for (const call of ctx.index.calls) {
      if (call.expression.getText() === 'sink' && call.arguments[0]) out.push(ctx.taint.trace(call.arguments[0], { context }));
    }
    return [];
  });
  return out;
}
