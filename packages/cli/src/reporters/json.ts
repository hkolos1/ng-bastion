import type { ReportingContext } from '../comparison.js';
import { summarizeFindings } from './overview.js';
import type { ScanResult } from '@ngbastion/core';

export const JSON_SCHEMA_VERSION = 1;
export const JSON_SCHEMA_URL = 'https://ngbastion.web.app/schemas/report-v1.json';

/**
 * Versioned JSON report (schema: packages/cli/schema/report-v1.json).
 * Paths are workspace-relative; no absolute paths or secrets are included.
 */
export function toJsonReport(result: ScanResult, configSources: string[] = [], context: ReportingContext = {}) {
  const { total, bySeverity } = summarizeFindings(result);
  return {
    $schema: JSON_SCHEMA_URL,
    schemaVersion: JSON_SCHEMA_VERSION,
    tool: result.tool,
    scan: {
      startedAt: result.startedAt,
      durationMs: result.durationMs,
      ...(result.angularVersion ? { angularVersion: result.angularVersion } : {}),
      projects: result.projects,
      config: { failOn: result.gate.failOn, minConfidence: result.gate.minConfidence, sources: configSources },
      stats: result.stats,
      ...(context.snapshot ? { snapshot: context.snapshot } : {}),
      ...(context.comparison ? { comparison: context.comparison } : {}),
      ...(context.git ? { git: context.git } : {}),
      gateScope: context.gateScope,
      identities: [...result.findings, ...result.suppressed].filter(f => f.fingerprintV2)
        .map(f => ({ legacy: f.fingerprint, v2: f.fingerprintV2 })),
    },
    rules: result.rules.map((r) => ({
      id: r.meta.id,
      name: r.meta.name,
      category: r.meta.category,
      severity: r.severity,
      level: r.level,
      ...(r.meta.cwe ? { cwe: r.meta.cwe } : {}),
      helpUri: `https://ngbastion.web.app/rules/${r.meta.id.toLowerCase()}`,
    })),
    findings: result.findings.map(({ fingerprintV2: _id, ...f }) => f),
    suppressed: result.suppressed.map(({ fingerprintV2: _id, ...f }) => f),
    diagnostics: result.diagnostics,
    summary: {
      total,
      bySeverity,
      suppressed: result.suppressed.length,
      hiddenBelowConfidence: result.stats.hiddenBelowConfidence,
      gate: { failOn: result.gate.failOn, failed: result.gate.failed, failingFindings: result.gate.failingFindings },
    },
  };
}

export function renderJson(result: ScanResult, configSources: string[] = [], context: ReportingContext = {}): string {
  return `${JSON.stringify(toJsonReport(result, configSources, context), null, 2)}\n`;
}
