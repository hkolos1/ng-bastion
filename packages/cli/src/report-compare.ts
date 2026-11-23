import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { Ajv } from 'ajv';
import type { toJsonReport } from './reporters/json.js';
import { compare, comparisonSummary } from './comparison.js';
import { parseSnapshot, ReportingError } from './baseline.js';

const require = createRequire(import.meta.url);
const validator = new Ajv({ strict: false, validateFormats: false });
const validate = validator.compile<ReturnType<typeof toJsonReport>>(require('../schema/report-v1.json'));

function reportSnapshot(file: string) {
  try {
    const report = JSON.parse(readFileSync(file, 'utf8'));
    if (report?.schemaVersion !== 1 || !report.scan?.snapshot) throw new Error('Missing comparison data. Generate JSON reports with the Reporting Release CLI.');
    if (!validate(report)) throw new Error('Invalid NgBastion JSON report: ' + validator.errorsText(validate.errors));
    const snapshot = parseSnapshot(report.scan.snapshot);
    const legacy = new Map(report.scan.identities.map(i => [i.legacy, i.v2]));
    const records = new Map(snapshot.findings.map(f => [f.fingerprint, f]));
    if (snapshot.scannerVersion !== report.tool.version || snapshot.createdAt !== report.scan.startedAt) throw new Error('Inconsistent snapshot header');
    for (const f of report.findings) {
      const id = legacy.get(f.fingerprint);
      const entry = id && records.get(id);
      if (!entry || entry.file !== f.location.file || entry.rule !== f.ruleId || entry.severity !== f.severity || entry.confidence !== f.confidence) throw new Error('Inconsistent finding snapshot');
      records.delete(entry.fingerprint);
    }
    if (records.size) throw new Error('Incomplete report findings');
    return snapshot;
  } catch (error) {
    throw new ReportingError(`Cannot compare report ${file}: ${(error as Error).message}`);
  }
}

export function compareReports(previous: string, current: string, format: 'terminal' | 'json') {
  const before = reportSnapshot(previous), after = reportSnapshot(current);
  const comparison = compare(before, after);
  const findings = after.findings.map(f => ({ ...f, status: comparison.statuses[f.fingerprint], reason: comparison.uncertainty[f.fingerprint] }));
  if (format === 'json') return JSON.stringify({ schemaVersion: 1, ...comparison, findings }, null, 2) + '\n';
  const lines = [comparisonSummary(comparison), ...comparison.warnings];
  for (const f of findings) lines.push(`${f.status}  ${f.rule}  ${f.file}  ${f.fingerprint}${f.reason ? '  ' + f.reason : ''}`);
  for (const f of comparison.resolved) lines.push(`resolved  ${f.rule}  ${f.file}  ${f.fingerprint}`);
  for (const { finding, reason } of comparison.unverified) lines.push(`unverified  ${finding.rule}  ${finding.file}  ${reason}`);
  for (const { previous: p, current: c } of comparison.changes) lines.push(`changed  ${c.rule}  ${c.file}  severity ${p.severity} → ${c.severity}, confidence ${p.confidence} → ${c.confidence}`);
  for (const [label, values] of Object.entries(comparison.coverage)) if (values.length) lines.push(label + ': ' + values.join(', '));
  return lines.join('\n') + '\n';
}
