import { renderHtmlDocument } from 'ngbastion/html-renderer';
import { savedAnalysis, scope, snippetProject, sourceRule } from './analysis';
import { rules } from './catalog';
import cli from '../../generated/cli.json';
import assets from '../../generated/report-assets.json';
import { boundedString, parameters } from './validation';

export function generateReport(input: unknown) {
  const args = parameters(input, ['analysisId']);
  const analysis = savedAnalysis(boundedString(args['analysisId'], 'analysisId', 64));
  if (!analysis) return { status: 'unknown_analysis' as const, message: 'Analyze the snippet again to generate a report.' };
  const html = renderHtmlDocument({
    ...analysis, tool: { version: cli.version }, projects: [{ name: snippetProject }],
    ruleCoverage: { available: rules.length, evaluated: [sourceRule.id] },
    rules: [{ meta: sourceRule, severity: sourceRule.defaultSeverity, level: 'warn' }],
    stats: { filesAnalyzed: 1, hiddenBelowConfidence: 0 }, gate: { failOn: 'none', failed: false },
    suppressed: [], diagnostics: [{ level: 'info', code: 'snippet-scope', message: scope }],
  }, assets);
  return { status: 'ok' as const, filename: 'ngbastion-snippet.html', mimeType: 'text/html', html };
}
