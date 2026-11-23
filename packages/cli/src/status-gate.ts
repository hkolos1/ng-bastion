import { confidenceRank, severityRank, type Confidence } from '@ngbastion/plugin-api';
import type { ScanResult } from '@ngbastion/core';
import type { ResolvedPolicy } from '@ngbastion/config';
import { ReportingError } from './baseline.js';
import type { Comparison } from './comparison.js';

export function statusGate(scan: ScanResult, policy: ResolvedPolicy, comparison?: Comparison, onlyNew = false, confidence?: Confidence): ScanResult {
  if (!onlyNew && !confidence) return scan;
  if (onlyNew && !comparison) throw new ReportingError('--fail-on-status new requires a baseline comparison');
  if (policy.maxFailOn || policy.mandatoryRules.size) throw new ReportingError('The configured security policy requires the full gate. Remove the status or confidence gate restriction.');
  const threshold = scan.gate.failOn;
  const failing = threshold === 'none' ? [] : scan.findings.filter(f => f.level === 'error'
    && severityRank(f.severity) >= severityRank(threshold)
    && (!confidence || confidenceRank(f.confidence) >= confidenceRank(confidence))
    && (!onlyNew || comparison?.statuses[f.fingerprintV2!] !== 'existing'));
  return { ...scan, gate: { ...scan.gate, failed: failing.length > 0, failingFindings: failing.length } };
}
