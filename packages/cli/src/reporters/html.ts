import { comparisonSummary, type ReportingContext } from '../comparison.js';
import { createHash } from 'node:crypto';
import { traceLocationKey } from '@ngbastion/core';
import type { EnabledRule, Finding, RelativeLocation, ScanResult } from '@ngbastion/core';
import { summarizeFindings } from './overview.js';
import { loadReportAssets } from '../report-assets.js';

const escape = (value: string | number) => String(value).replace(/[&<>"']/g, c =>
  ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!);
const position = (loc: RelativeLocation) => `${loc.file}:${loc.line}:${loc.column}`;
const digest = (text: string) => createHash('sha256').update(text).digest('base64');
const filterFields = ['severity', 'confidence', 'rule', 'category', 'file', 'status'] as const;

function distribution(label: string, counts: Record<string, number>, total: number) {
  return `<section><h3>${label}</h3><ul class="distribution">${Object.entries(counts).map(([value, count]) => {
    return `<li><span>${escape(value)}</span><meter class="${escape(value)}" aria-label="${escape(value)} findings" min="0" max="${Math.max(1, total)}" value="${count}"></meter><b>${count}</b></li>`;
  }).join('')}</ul></section>`;
}

// Token decoration only. Every matched token and intervening slice is encoded as text.
function highlight(line: string) {
  const tokens = /("(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|`[^`]*`)|(\b(?:export|import|const|let|return|class|new|function|this|async|await|if|from)\b)|(<\/?[\w-]+)|([\w$]+)(?=\s*\()/g;
  let html = '';
  let offset = 0;
  for (const token of line.matchAll(tokens)) {
    html += escape(line.slice(offset, token.index));
    const kind = token[1] ? 'literal' : token[2] ? 'keyword' : 'symbol';
    html += `<span class="${kind}">${escape(token[0])}</span>`;
    offset = token.index + token[0].length;
  }
  return html + escape(line.slice(offset));
}

function findingCard(f: Finding, rule: EnabledRule | undefined, index: number, redact: boolean, limited: boolean, context: ReportingContext, excerpts?: ReadonlyMap<string, string>) {
  const e = escape;
  const id = `finding-${index}`;
  const status = f.suppression ? 'Suppressed' : context.comparison?.statuses[f.fingerprintV2!] ?? 'Uncompared';
  const git = context.git?.findings[f.fingerprintV2!];
  const reason = context.comparison?.uncertainty?.[f.fingerprintV2!];
  const docs = rule?.meta.docs;
  const docLink = /^NGB\d{3}$/.test(f.ruleId)
    ? `<a href="https://ngbastion.web.app/rules/${f.ruleId.toLowerCase()}" rel="noreferrer">Rule documentation</a>` : '';
  const trace = f.trace?.map((step, ordinal) => {
    const excerpt = !redact && excerpts?.get(traceLocationKey(step));
    return `<li class="step ${e(step.kind)}"><strong>${e(step.kind)}</strong>
      ${redact ? '' : e(step.description)} ${!redact && step.symbol ? `<code>${e(step.symbol)}</code>` : ''}
      <code class="trace-location">${e(position(step))}</code>
      ${excerpt ? `<details><summary>View expression</summary><pre><code><span class="line-number">${e(step.line)}</span> ${highlight(excerpt)}</code></pre></details>` : ''}
      ${step.kind === 'sink' ? `<a href="#${id}-location">View finding location</a>` : `<a href="#${id}-location" class="focus-link">Finding details for step ${ordinal + 1}</a>`}
      </li>`;
  }).join('');
  const snippet = !redact && f.snippet !== undefined
    ? `<pre><code><span class="line-number">${e(f.location.line)}</span> ${highlight(f.snippet)}</code></pre>`
    : '<p>Source text withheld or unavailable.</p>';
  return `<details class="finding" data-change="${e(git ?? '')}" data-severity="${e(f.severity)}" data-confidence="${e(f.confidence)}" data-rule="${e(f.ruleId)}" data-category="${e(f.category)}" data-file="${e(f.location.file)}" data-status="${e(status)}" data-line="${e(f.location.line)}" data-column="${e(f.location.column)}">
    <summary><span class="badge ${e(f.severity)}">${e(f.severity)}</span> <span class="rule-id">${e(f.ruleId)}</span> <strong>${e(f.ruleName)}</strong>
    <small>${e(position(f.location))} · ${e(f.confidence)} confidence · ${e(status)}${git ? ' · ' + e(git) : ''}</small></summary>
    <div class="detail">${reason ? `<p>Comparison uncertainty · ${e(reason)}</p>` : ''}<p>${e(docs?.description ?? '')}</p>${redact ? '' : `<p>${e(f.message)}</p>`}
    <p>${e(f.category)} · ${e(f.evidenceKind)} · ${e(f.project)} · ${e(f.level)}</p>
    <h4 id="${id}-location" tabindex="-1">Finding location</h4><code>${e(position(f.location))}</code>${snippet}
    ${trace ? `<h4>Source-to-sink evidence</h4>${limited ? '<p>Analysis limits were reached during this scan. Completeness of individual paths is unknown.</p>' : ''}<ol class="trace">${trace}</ol>` : ''}
    ${!redact && f.evidence.length ? `<ul>${f.evidence.map(s => `<li>${e(s)}</li>`).join('')}</ul>` : ''}
    ${f.suppression ? `<p>Suppression · ${e(f.suppression.kind)}${redact ? '' : ' · ' + e(f.suppression.justification)}</p>` : ''}
    <h4>Remediation</h4><p>${e(docs?.remediation ?? 'Consult the rule author for guidance.')}</p>
    <p>${(rule?.meta.cwe ?? []).map(e).join(' · ')} ${(docs?.references ?? []).filter(r => /OWASP/i.test(r.title)).map(r => e(r.title)).join(' · ')} ${docLink}</p>
    <p>Fingerprint <code>${e(f.fingerprintV2 ?? f.fingerprint)}</code></p></div></details>`;
}

export function renderHtml(result: ScanResult, options: ReportingContext & { redactSource?: boolean } = {}) {
  const assets = loadReportAssets();
  const csp = `default-src 'none'; script-src 'sha256-${digest(assets.script)}'; style-src 'sha256-${digest(assets.style)}'; font-src data:; base-uri 'none'; form-action 'none'; object-src 'none'`;
  const { findings, diagnostics, stats, ruleCoverage } = result;
  const ruleMap = new Map(result.rules.map(rule => [rule.meta.id, rule]));
  const incomplete = diagnostics.filter(d => ['analysis-incomplete', 'analysis-timeout'].includes(d.code));
  const { bySeverity, byConfidence, total } = summarizeFindings(result);
  const counts = [
    ['Active findings', findings.length], ['TS files analyzed', stats.filesAnalyzed], ['Available rules', ruleCoverage?.available ?? 'Unknown'],
    ['Enabled rules', ruleMap.size], ['Applicable rules', 'Unmeasured'], ['Evaluated rules¹', ruleCoverage?.evaluated.length ?? 'Unknown'],
  ] as const;
  const cards = [...findings, ...result.suppressed].map((f, i) => findingCard(f, ruleMap.get(f.ruleId), i, !!options.redactSource, incomplete.length > 0, options, result.traceContext));
  const project = result.projects.map(p => p.name).join(', ') || 'No project analyzed';
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="${escape(csp)}">
<meta name="viewport" content="width=device-width,initial-scale=1"><meta name="referrer" content="no-referrer"><title>NgBastion · ${escape(project)}</title><style>${assets.style}</style></head>
<body><a class="skip" href="#findings">Skip to findings</a><header><div class="wrap bar"><b class="brand">${assets.mark} NgBastion</b><button hidden id="theme" type="button">Switch theme</button></div></header>
<main class="wrap"><p class="eyebrow">Security report</p><h1>${escape(project)}</h1><p class="meta">NgBastion ${escape(result.tool.version)} · <time>${escape(result.startedAt)}</time> · ${escape(result.durationMs)} ms</p>
<h2>Scan overview</h2><dl class="metrics">${counts.map(([name, count]) => `<div><dt>${name}</dt><dd>${escape(count)}</dd></div>`).join('')}</dl>
<p>¹ Unique rules that completed in at least one project. Individual rules determine relevance internally.</p>
<div class="charts">${distribution('Severity', bySeverity, total)}${distribution('Confidence', byConfidence, total)}</div>
<p>Gate ${options.gateScope ? `(${escape(options.gateScope.status)}, confidence ${escape(options.gateScope.confidence ?? 'low')}+) ` : ''}${result.gate.failOn === 'none' ? 'disabled' : result.gate.failed ? 'failed' : 'passed'} · ${result.suppressed.length} suppressed · ${escape(stats.hiddenBelowConfidence)} below confidence threshold · ${incomplete.length} analysis limit diagnostics</p>
${options.git ? `<p>Git working tree compared with <code>${escape(options.git.revision)}</code> · ${options.git.files.length} changed paths. Associations include recorded trace locations.</p>` : ''}<p>${options.comparison ? escape(comparisonSummary(options.comparison)) : 'Baseline comparison unavailable. New, existing and resolved counts require comparison data.'}</p>
${options.comparison ? `<details><summary>Comparison details</summary><ul>${[...options.comparison.warnings, ...options.comparison.resolved.map(f => 'Resolved · ' + f.rule + ' · ' + f.file), ...options.comparison.unverified.map(u => u.finding.rule + ' · ' + u.finding.file + ' · ' + u.reason)].map(s => '<li>' + escape(s) + '</li>').join('')}</ul></details>` : ''}
${!findings.length ? '<p>No active findings within this scan’s coverage.</p>' : ''}
${diagnostics.length ? `<details class="diagnostics"><summary>Scan diagnostics (${diagnostics.length})</summary><ul>${diagnostics.map(d => `<li>${escape(d.level)} · <b>${escape(d.code)}</b> ${escape(d.file ?? '')} ${options.redactSource ? '' : escape(d.message)}</li>`).join('')}</ul></details>` : ''}
<section id="findings"><h2>Findings explorer</h2><div id="controls" hidden><label>Search findings<input id="search" type="search"></label>
${(options.git ? [...filterFields, 'change'] : filterFields).map(field => `<label>${field}<select id="${field}" data-filter><option value="">All</option></select></label>`).join('')}
<label>Sort by<select id="sort"><option>Severity</option><option>Confidence</option><option>Location</option><option>Rule ID</option></select></label><button id="reset">Reset filters</button></div>
<p role="status" id="matches"></p><div id="rows">${cards.join('')}</div><nav hidden id="pages" aria-label="Finding pages"><button id="prev">Previous</button><button id="next">Next</button></nav></section></main>
<script>${assets.script}</script></body></html>\n`;
}
