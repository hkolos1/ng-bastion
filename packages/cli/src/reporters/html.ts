import { traceLocationKey, type ScanResult } from '@ngbastion/core';
import { comparisonSummary, type ReportingContext } from '../comparison.js';
import { loadReportAssets } from '../report-assets.js';
import { renderHtmlDocument } from '../html-renderer.js';

export function renderHtml(result: ScanResult, options: ReportingContext & { redactSource?: boolean } = {}) {
  return renderHtmlDocument(result, loadReportAssets(), {
    ...options,
    comparisonLabel: options.comparison && comparisonSummary(options.comparison),
    excerptFor: step => result.traceContext?.get(traceLocationKey(step)),
  });
}
