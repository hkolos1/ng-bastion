import type { GitClassification } from './git-diff.js';
import { createHash } from 'node:crypto';
import type { ResolvedConfig } from '@ngbastion/config';
import { FINGERPRINT_VERSION, type ScanResult } from '@ngbastion/core';
import type { Confidence, Severity } from '@ngbastion/plugin-api';

export interface Entry {
  fingerprint: string;
  rule: string;
  file: string;
  severity: Severity;
  confidence: Confidence;
}

export interface Snapshot {
  schemaVersion: 1;
  fingerprintVersion: number;
  scannerVersion: string;
  createdAt: string;
  configHash: string;
  files: string[];
  rules: string[];
  projects: string[];
  limitations: string[];
  inactive: string[];
  findings: Entry[];
}

export type Status = 'new' | 'existing' | 'uncertain';

export interface Comparison {
  new: number;
  existing: number;
  uncertain: number;
  resolved: Entry[];
  unverified: { finding: Entry; reason: string }[];
  changes: { previous: Entry; current: Entry }[];
  statuses: Record<string, Status>;
  coverage: { addedFiles: string[]; removedFiles: string[]; enabledRules: string[]; disabledRules: string[] };
  warnings: string[];
}

export interface ReportingContext {
  git?: GitClassification;
  snapshot?: Snapshot;
  comparison?: Comparison;
  gateScope?: { status: 'all' | 'new'; confidence?: Confidence };
}

function canonical(_key: string, value: unknown) {
  if (value && typeof value === 'object' && !Array.isArray(value)) {
    return Object.fromEntries(Object.entries(value).sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0));
  }
  return value;
}

export function snapshot(result: ScanResult, config: ResolvedConfig): Snapshot {
  const relevant = {
    rules: config.rules, include: config.include, exclude: config.exclude, projects: config.projects,
    limits: config.limits, minConfidence: config.minConfidence, sanitizers: config.trustedSanitizers,
    plugins: config.plugins.map(p => p.specifier), exceptions: config.exceptions.map(({ source: _source, ...e }) => e),
    inline: config.policy.allowInlineSuppressions, angular: result.angularVersion,
  };
  const limitations = result.diagnostics.filter(d => d.code !== 'angular-workspace-not-found').map(d => d.code);
  if (config.plugins.length) limitations.push('plugin-version-unverified');
  if (!result.comparisonCoverage || !result.ruleCoverage) limitations.push('missing-coverage');
  return {
    schemaVersion: 1, fingerprintVersion: FINGERPRINT_VERSION, scannerVersion: result.tool.version,
    createdAt: result.startedAt, configHash: createHash('sha256').update(JSON.stringify(relevant, canonical)).digest('hex'),
    limitations: [...new Set(limitations)].sort(), files: result.comparisonCoverage?.files ?? [],
    rules: [...(result.ruleCoverage?.evaluated ?? [])].sort(), projects: result.projects.map(p => p.name).sort(),
    inactive: [...(result.comparisonCoverage?.hidden ?? []), ...result.suppressed.map(f => f.fingerprintV2!)].sort(),
    findings: result.findings.map(f => ({ fingerprint: f.fingerprintV2!, rule: f.ruleId, file: f.location.file, severity: f.severity, confidence: f.confidence }))
      .sort((a, b) => a.fingerprint.localeCompare(b.fingerprint)),
  };
}

export function compare(before: Snapshot, after: Snapshot): Comparison {
  const warnings: string[] = [];
  if (before.fingerprintVersion !== after.fingerprintVersion) throw new Error('incompatible fingerprint versions');
  if (before.scannerVersion !== after.scannerVersion) warnings.push('Scanner version changed');
  if (before.configHash !== after.configHash) warnings.push('Analysis configuration changed');
  if (JSON.stringify(before.projects) !== JSON.stringify(after.projects)) warnings.push('Project selection changed');
  const prior = new Map(before.findings.map(f => [f.fingerprint, f]));
  const current = new Set(after.findings.map(f => f.fingerprint));
  const difference = (a: string[], b: string[]) => {
    const other = new Set(b);
    return a.filter(value => !other.has(value)).sort();
  };
  const coverage = {
    addedFiles: difference(after.files, before.files), removedFiles: difference(before.files, after.files),
    enabledRules: difference(after.rules, before.rules), disabledRules: difference(before.rules, after.rules),
  };
  function absenceReason(s: Snapshot) {
    const rules = new Set(s.rules), files = new Set(s.files), inactive = new Set(s.inactive);
    return (f: Entry) => {
      if (inactive.has(f.fingerprint)) return 'Suppressed or below the confidence threshold';
      if (!rules.has(f.rule)) return 'Rule did not complete';
      if (!files.has(f.file)) return 'File outside observed coverage';
      if (warnings.length) return warnings.join('. ');
      if (s.limitations.length) return 'Limited analysis: ' + s.limitations.join(', ');
      if (coverage.removedFiles.length || coverage.addedFiles.length) return 'File coverage changed across the project';
      return undefined;
    };
  }
  const oldReason = absenceReason(before), newReason = absenceReason(after);
  const result: Comparison = { new: 0, existing: 0, uncertain: 0, resolved: [], unverified: [], changes: [], statuses: Object.create(null), warnings: [...warnings], coverage };
  for (const f of after.findings) {
    const old = prior.get(f.fingerprint);
    const status = old ? 'existing' : oldReason(f) ? 'uncertain' : 'new';
    result.statuses[f.fingerprint] = status;
    result[status]++;
    if (old && (old.confidence !== f.confidence || old.severity !== f.severity)) result.changes.push({ previous: old, current: f });
  }
  for (const old of before.findings) {
    if (current.has(old.fingerprint)) continue;
    const reason = newReason(old);
    if (reason) result.unverified.push({ finding: old, reason });
    else result.resolved.push(old);
  }
  if (before.limitations.length) result.warnings.push('Previous scan: ' + before.limitations.join(', '));
  if (after.limitations.length) result.warnings.push('Current scan: ' + after.limitations.join(', '));
  return result;
}

export function comparisonSummary(c: Comparison) {
  return `Baseline: ${c.new} new, ${c.existing} existing, ${c.uncertain} uncertain, ${c.resolved.length} resolved, ${c.unverified.length} unverified disappearances`;
}
