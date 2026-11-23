import type { HtmlReportInput } from 'ngbastion/html-renderer';
import { documentation, rules } from './catalog';
import { boundedString, InputError, parameters } from './validation';
import { runWorker } from './worker-client';

export const scope = 'Single-file TypeScript literal analysis for NGB018 only. JSON configuration, Angular templates, project data flow and policy are outside this scan.';
export const sourceRule = rules.find(r => r.id === 'NGB018')!;
export const snippetProject = 'TypeScript snippet · NGB018 source literals';
const recent = new Map<string, { findings: HtmlReportInput['findings']; startedAt: string; durationMs: number }>();

export function savedAnalysis(id: string) { return recent.get(id); }

export async function analyzeSnippet(input: unknown, signal?: AbortSignal) {
  try {
    const args = parameters(input, ['code', 'filename', 'ruleIds', 'language']);
    const code = boundedString(args['code'], 'code', 32768);
    const filename = args['filename'] === undefined ? 'snippet.ts' : boundedString(args['filename'], 'filename', 100);
    if (!/^[a-zA-Z0-9][a-zA-Z0-9_.-]*\.ts$/.test(filename) || filename.includes('..') || filename.endsWith('.d.ts')) {
      throw new InputError('Provide a plain TypeScript filename such as component.ts.');
    }
    const language = args['language'] === undefined ? 'typescript' : boundedString(args['language'], 'language', 32);
    const ids = args['ruleIds'];
    if (ids !== undefined && (!Array.isArray(ids) || !ids.length || ids.length > rules.length ||
        ids.some(id => !rules.some(r => r.id === id)) || new Set(ids).size !== ids.length)) {
      throw new InputError('ruleIds must contain distinct known rule IDs.');
    }
    const selected = ids === undefined ? rules : rules.filter(r => ids.includes(r.id));
    const rulesSkipped = selected.filter(r => r !== sourceRule).map(r => r.id);
    const coverage = { limitations: [scope], rulesExecuted: [] as string[], rulesSkipped: selected.map(r => r.id) };
    if (!selected.includes(sourceRule) || language !== 'typescript') {
      return { status: 'unsupported' as const, message: scope, ...coverage };
    }
    const startedAt = new Date().toISOString();
    const start = performance.now();
    const result = await runWorker({ code, filename }, signal);
    const durationMs = Math.round(performance.now() - start);
    if (result.status !== 'ok') return { ...result, ...coverage, analysisDurationMs: durationMs };
    const findings = result.findings.map(hit => ({ ...hit, severity: hit.severity ?? sourceRule.defaultSeverity,
      ruleId: sourceRule.id, ruleName: sourceRule.name, category: sourceRule.category, project: snippetProject, level: 'warn' as const,
      recommendation: sourceRule.docs.remediation, documentation: documentation(sourceRule.id) }));
    const analysisId = crypto.randomUUID();
    recent.set(analysisId, { findings, startedAt, durationMs });
    if (recent.size > 4) recent.delete(recent.keys().next().value!);
    return { status: 'ok' as const, analysisId, analysisDurationMs: durationMs, summary: { total: findings.length },
      findings, rulesExecuted: [sourceRule.id], rulesSkipped, limitations: [scope] };
  } catch (error) {
    return { status: 'error' as const, message: error instanceof InputError ? error.message : 'Snippet analysis failed.' };
  }
}
