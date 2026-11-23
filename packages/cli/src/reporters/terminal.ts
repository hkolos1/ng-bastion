import { comparisonSummary, type ReportingContext } from '../comparison.js';
import { SEVERITIES, type Severity } from '@ngbastion/plugin-api';
import type { Finding, ScanResult } from '@ngbastion/core';

export interface Colors {
  bold(s: string): string;
  dim(s: string): string;
  red(s: string): string;
  yellow(s: string): string;
  blue(s: string): string;
  green(s: string): string;
  magenta(s: string): string;
  cyan(s: string): string;
}

export function createColors(enabled: boolean): Colors {
  const wrap = (open: number, close: number) => (s: string) => (enabled ? `\u001b[${open}m${s}\u001b[${close}m` : s);
  return {
    bold: wrap(1, 22), dim: wrap(2, 22), red: wrap(31, 39), green: wrap(32, 39), yellow: wrap(33, 39),
    blue: wrap(34, 39), magenta: wrap(35, 39), cyan: wrap(36, 39),
  };
}

export interface TerminalOptions extends ReportingContext {
  colors: Colors;
  verbose?: boolean;
  quiet?: boolean;
  showSuppressed?: boolean;
  remediation?: (ruleId: string) => string | undefined;
}

const KIND_WIDTH = 12;

function severityLabel(s: Severity, c: Colors): string {
  const label = s.toUpperCase().padEnd(8);
  if (s === 'critical') return c.bold(c.magenta(label));
  if (s === 'high') return c.bold(c.red(label));
  if (s === 'medium') return c.yellow(label);
  return c.blue(label);
}

function firstSentence(text: string): string {
  const m = /^(.+?[.!?])(\s|$)/.exec(text);
  return m ? m[1]! : text;
}

function renderFinding(f: Finding, o: TerminalOptions): string[] {
  const c = o.colors;
  const lines = [
    `${severityLabel(f.severity, c)} ${c.bold(f.ruleId)}  ${f.ruleName}  ${c.dim(`confidence: ${f.confidence} · ${f.evidenceKind}${f.level === 'warn' ? ' · warn' : ''}`)}`,
    `  ${c.cyan(`${f.location.file}:${f.location.line}:${f.location.column}`)}`,
    ...(o.comparison && !f.suppression ? [`  Status: ${o.comparison.statuses[f.fingerprintV2!]}`] : []),
    `  ${f.message}`,
  ];
  if (f.snippet) lines.push(`  ${c.dim('│')} ${f.snippet}`);
  if (f.trace?.length) {
    lines.push(`  ${c.dim('Trace:')}`);
    f.trace.forEach((s, i) => {
      lines.push(`    ${c.dim(`${i + 1}.`)} ${s.kind.padEnd(KIND_WIDTH)} ${c.cyan(`${s.file}:${s.line}:${s.column}`)}  ${s.description}`);
    });
  }
  if (o.verbose && f.evidence.length) {
    lines.push(`  ${c.dim('Evidence:')}`);
    for (const e of f.evidence) lines.push(`    - ${e}`);
  }
  if (f.suppression) lines.push(`  ${c.dim(`Suppressed (${f.suppression.kind}, ${f.suppression.source}): ${f.suppression.justification}`)}`);
  const fix = o.remediation?.(f.ruleId);
  if (fix && !f.suppression) lines.push(`  ${c.green('Fix:')} ${firstSentence(fix)} ${c.dim(`→ ngbastion explain ${f.ruleId}`)}`);
  return lines;
}

export function renderTerminal(result: ScanResult, o: TerminalOptions): string {
  const c = o.colors;
  const out: string[] = [];
  const files = result.stats.filesAnalyzed;
  out.push(c.bold(`NgBastion ${result.tool.version}`) + c.dim(` · ${result.projects.length} project(s) · ${files} file(s) · ${result.stats.templatesAnalyzed} template(s) · ${(result.durationMs / 1000).toFixed(1)}s`));
  out.push('');

  if (!o.quiet) {
    for (const f of result.findings) out.push(...renderFinding(f, o), '');
    if (o.showSuppressed) for (const f of result.suppressed) out.push(...renderFinding(f, o), '');
  }

  const diags = result.diagnostics.filter((d) => o.verbose || d.level !== 'info');
  if (diags.length && !o.quiet) {
    out.push(c.bold('Diagnostics'));
    for (const d of diags) {
      const tag = d.level === 'error' ? c.red('error  ') : d.level === 'warning' ? c.yellow('warning') : c.dim('info   ');
      out.push(`  ${tag} ${c.dim(d.code)} ${d.message}${d.file ? c.dim(` (${d.file})`) : ''}`);
    }
    const hiddenInfo = result.diagnostics.length - diags.length;
    if (hiddenInfo) out.push(c.dim(`  ${hiddenInfo} informational diagnostic(s) hidden; use --verbose`));
    out.push('');
  }

  const counts = [...SEVERITIES].reverse()
    .map((s) => [s, result.findings.filter((f) => f.severity === s).length] as const)
    .filter(([, n]) => n > 0)
    .map(([s, n]) => `${n} ${s}`);
  const parts = [`${result.findings.length} finding(s)${counts.length ? ` (${counts.join(', ')})` : ''}`];
  if (result.suppressed.length) parts.push(`${result.suppressed.length} suppressed`);
  if (result.stats.hiddenBelowConfidence) parts.push(`${result.stats.hiddenBelowConfidence} below confidence '${result.gate.minConfidence}' hidden`);
  out.push(`${c.bold('Summary:')} ${parts.join(' · ')}`);
  if (!result.findings.length) {
    out.push(c.dim('No findings does not prove the application is secure: NgBastion only reports the patterns and data flows it models.'));
  }
  if (o.comparison) out.push(comparisonSummary(o.comparison), ...o.comparison.warnings);
  if (o.gateScope?.status === 'new' || o.gateScope?.confidence) out.push(`Gate scope: ${o.gateScope.status} · confidence ${o.gateScope.confidence ?? 'low'}+`);
  const gate = result.gate;
  if (gate.failOn === 'none') out.push(`${c.bold('Security gate:')} disabled (failOn: none)`);
  else if (gate.failed) out.push(`${c.bold('Security gate')} (fail on ${gate.failOn}+): ${c.red(c.bold('FAILED'))} — ${gate.failingFindings} finding(s) at or above '${gate.failOn}'`);
  else out.push(`${c.bold('Security gate')} (fail on ${gate.failOn}+): ${c.green('passed')}`);
  return `${out.join('\n')}\n`;
}
