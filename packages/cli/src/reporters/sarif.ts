import type { ReportingContext } from '../comparison.js';
import type { Severity } from '@ngbastion/plugin-api';
import type { Finding, ScanResult } from '@ngbastion/core';

const LEVEL: Record<Severity, 'error' | 'warning' | 'note'> = { critical: 'error', high: 'error', medium: 'warning', low: 'note', info: 'note' };
/** GitHub code scanning reads `security-severity` (0–10) to bucket alerts. */
const SECURITY_SEVERITY: Record<Severity, string> = { critical: '9.5', high: '8.0', medium: '5.5', low: '3.0', info: '1.0' };
const PRECISION = { high: 'high', medium: 'medium', low: 'low' } as const;

function location(file: string, region: { line: number; column: number; endLine: number; endColumn: number }, message?: string) {
  return {
    physicalLocation: {
      artifactLocation: { uri: encodeURI(file), uriBaseId: '%SRCROOT%' },
      region: { startLine: region.line, startColumn: region.column, endLine: region.endLine, endColumn: region.endColumn },
    },
    ...(message ? { message: { text: message } } : {}),
  };
}

function result(f: Finding, ruleIndex: number, context: ReportingContext) {
  const status = context.comparison?.statuses[f.fingerprintV2!];
  const changed = context.comparison?.changes.some(c => c.current.fingerprint === f.fingerprintV2);
  return {
    ruleId: f.ruleId,
    ruleIndex,
    level: LEVEL[f.severity],
    message: { text: f.message },
    locations: [location(f.location.file, f.location)],
    partialFingerprints: { 'ngbastion/v1': f.fingerprint, ...(f.fingerprintV2 ? { 'ngbastion/v2': f.fingerprintV2 } : {}) },
    ...(status === 'existing' ? { baselineState: changed ? 'updated' : 'unchanged' } : status === 'new' ? { baselineState: 'new' } : {}),
    ...(f.trace?.length
      ? {
          codeFlows: [{
            message: { text: `${f.trace[0]!.description} → ${f.trace[f.trace.length - 1]!.description}` },
            threadFlows: [{ locations: f.trace.map((s) => ({ location: location(s.file, s, `${s.kind}: ${s.description}`) })) }],
          }],
        }
      : {}),
    ...(f.suppression
      ? { suppressions: [{ kind: f.suppression.kind === 'inline' ? 'inSource' : 'external', status: 'accepted', justification: f.suppression.justification }] }
      : {}),
    properties: { ...(context.git ? { gitAssociation: context.git.findings[f.fingerprintV2!] } : {}), ...(status ? { findingStatus: status } : {}), severity: f.severity, confidence: f.confidence, evidenceKind: f.evidenceKind, evidence: f.evidence, project: f.project },
  };
}

/** SARIF 2.1.0 log compatible with GitHub code scanning. */
export function toSarif(result_: ScanResult, context: ReportingContext = {}) {
  const rules = result_.rules;
  const index = new Map(rules.map((r, i) => [r.meta.id, i]));
  const all = [...result_.findings, ...result_.suppressed];
  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [{
      tool: {
        driver: {
          name: 'NgBastion',
          semanticVersion: result_.tool.version,
          version: result_.tool.version,
          informationUri: 'https://ngbastion.web.app',
          rules: rules.map((r) => ({
            id: r.meta.id,
            name: r.meta.name.replace(/(^|[\s/-]+)(\w)/g, (_, __, c: string) => c.toUpperCase()).replace(/\W/g, ''),
            shortDescription: { text: r.meta.name },
            fullDescription: { text: r.meta.docs.description },
            helpUri: `https://ngbastion.web.app/rules/${r.meta.id.toLowerCase()}`,
            help: {
              text: `${r.meta.docs.rationale}\n\nRemediation: ${r.meta.docs.remediation}`,
              markdown: `${r.meta.docs.rationale}\n\n**Remediation:** ${r.meta.docs.remediation}\n\n[Rule documentation](https://ngbastion.web.app/rules/${r.meta.id.toLowerCase()})`,
            },
            defaultConfiguration: { level: LEVEL[r.severity] },
            properties: {
              tags: ['security', r.meta.category, ...(r.meta.cwe ?? []).map((c) => `external/cwe/${c.toLowerCase()}`)],
              precision: PRECISION.medium,
              'security-severity': SECURITY_SEVERITY[r.severity],
              'problem.severity': LEVEL[r.severity] === 'note' ? 'recommendation' : LEVEL[r.severity],
            },
          })),
        },
      },
      automationDetails: { id: 'ngbastion/' },
      ...(context.comparison ? { properties: { comparison: context.comparison } } : {}),
      columnKind: 'utf16CodeUnits',
      results: all.map((f) => result(f, index.get(f.ruleId) ?? 0, context)),
      invocations: [{
        executionSuccessful: !result_.diagnostics.some((d) => d.level === 'error'),
        toolExecutionNotifications: result_.diagnostics.map((d) => ({
          level: d.level === 'info' ? 'note' : d.level,
          message: { text: `${d.code}: ${d.message}` },
          ...(d.file ? { locations: [{ physicalLocation: { artifactLocation: { uri: encodeURI(d.file), uriBaseId: '%SRCROOT%' } } }] } : {}),
        })),
      }],
    }],
  };
}

export function renderSarif(result: ScanResult, context: ReportingContext = {}): string {
  return `${JSON.stringify(toSarif(result, context), null, 2)}\n`;
}
