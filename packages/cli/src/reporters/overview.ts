import type { ScanResult } from '@ngbastion/core';
import { CONFIDENCES, SEVERITIES, type Confidence, type Severity } from '@ngbastion/plugin-api';

/** Counts cover active findings after the scanner applies confidence and suppression policy. */
export function summarizeFindings({ findings }: Pick<ScanResult, 'findings'>) {
  const bySeverity = Object.fromEntries([...SEVERITIES].reverse().map(s => [s, 0])) as Record<Severity, number>;
  const byConfidence = Object.fromEntries([...CONFIDENCES].reverse().map(c => [c, 0])) as Record<Confidence, number>;
  for (const finding of findings) {
    bySeverity[finding.severity]++;
    byConfidence[finding.confidence]++;
  }
  return { total: findings.length, bySeverity, byConfidence };
}
