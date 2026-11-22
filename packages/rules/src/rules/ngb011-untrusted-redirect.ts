import type * as ts from 'typescript';
import { defineRule, minConfidence, type AnalysisContext, type RuleFinding } from '@ngbastion/plugin-api';
import { constantPrefix, flowEvidence, hasFixedOrigin, is, isGlobalCall, memberName, receiverOf, sinkStep, strip } from '../shared/common.js';
import { urlValidation, valueNames } from '../shared/url-guards.js';

export interface NavigationSink {
  node: ts.Node;
  value: ts.Expression;
  description: string;
  /** Top-level navigation (window/location) vs. element attribute (anchor/iframe). */
  kind: 'navigation' | 'element';
}

const isLocation = (ctx: AnalysisContext, e: ts.Expression) => is(ctx.symbols.typeOrigin(e), 'dom', 'Location');

/** Browser navigation sinks: `location = v`, `location.href = v`, `location.assign/replace(v)`, `window.open(v)`. */
export function navigationSinks(ctx: AnalysisContext): NavigationSink[] {
  const out: NavigationSink[] = [];
  for (const a of ctx.index.assignments) {
    const left = strip(ctx, a.left);
    if (memberName(ctx, left) === 'href' && isLocation(ctx, receiverOf(ctx, left)!)) {
      out.push({ node: a, value: a.right, description: 'location.href assignment', kind: 'navigation' });
    } else if (isLocation(ctx, left) || (memberName(ctx, left) === 'location' && is(ctx.symbols.typeOrigin(receiverOf(ctx, left)!), 'dom', 'Window', 'Document'))) {
      out.push({ node: a, value: a.right, description: 'location assignment', kind: 'navigation' });
    }
  }
  for (const call of ctx.index.calls) {
    const info = ctx.symbols.callee(call);
    const arg = call.arguments[0];
    if (!info || !arg || info.declaration) continue;
    const recv = receiverOf(ctx, strip(ctx, call.expression));
    if ((info.name === 'assign' || info.name === 'replace') && recv && isLocation(ctx, recv)) {
      out.push({ node: call, value: arg, description: `location.${info.name}()`, kind: 'navigation' });
    } else if (info.name === 'open' && (recv ? is(info.receiver, 'dom', 'Window') : isGlobalCall(info, 'open'))) {
      out.push({ node: call, value: arg, description: 'window.open()', kind: 'navigation' });
    }
  }
  return out;
}

/** Constant prefix that pins the destination to this application (`/app/…`) or one origin (`https://host/…`). */
export function pinnedDestination(prefix: string | undefined): boolean {
  if (!prefix) return false;
  if (hasFixedOrigin(prefix)) return true;
  return prefix.length > 1 && prefix[0] === '/' && prefix[1] !== '/' && prefix[1] !== '\\';
}

export const ngb011 = defineRule({
  meta: {
    id: 'NGB011',
    name: 'Untrusted redirect',
    category: 'navigation-auth',
    defaultSeverity: 'high',
    cwe: ['CWE-601'],
    docs: {
      description:
        'Reports untrusted data (URL parameters, postMessage data, window.name, referrer, HTTP responses, storage) that controls the destination of a browser navigation — `location.href = v`, `location = v`, `location.assign()/replace()`, `window.open()` — including redirect helper functions that receive the URL as a parameter. Navigation through the Angular Router (`navigate()`, `navigateByUrl()`) is application-internal and never reported.',
      rationale:
        'Open redirects let attackers use your trusted domain to bounce victims to phishing pages (`/login?returnUrl=https://evil.example`), and they frequently break OAuth / SSO flows that rely on redirect allowlists.',
      patterns: [
        '`window.location.href = v`, `location = v`, `document.location = v`, `location.assign(v)`, `location.replace(v)`, `window.open(v)`',
        'Redirect helpers: `function go(url) { location.href = url }` traced back to its callers',
        'Recognized host validation guarding the sink (if / early return / ternary / &&): same-origin comparison (`new URL(u, location.origin).origin === location.origin`), host or origin allowlists (`ALLOWED.includes(new URL(u).hostname)`, `.has()`), relative paths (`u.startsWith("/") && !u.startsWith("//")`), prefix checks against a constant `https://host/` or a configured API URL, anchored origin regexes',
        'A constant prefix pinning the destination (`"/account/" + id`, `` `https://example.com/${path}` ``) is not reported',
      ],
      limitations: [
        'Only guards inside the function containing the sink are considered; validation performed by a caller of a redirect helper is not seen.',
        'Validation inside a project function used as a guard (`if (isSafeUrl(u))`) is not analyzed; the finding is kept with low confidence.',
        '`u.startsWith("/") && !u.startsWith("//")` is accepted as a relative-path check; browsers also treat `/\\evil.example` as protocol-relative, so also reject backslashes.',
      ],
      falsePositives: [
        'Destinations already validated by a server-side allowlist before reaching the client.',
        'Weak checks such as `url.includes("example.com")` lower the confidence but are still reported because they are bypassable (`https://evil.example/?example.com`).',
      ],
      remediation:
        'Accept only relative paths or compare the parsed origin with an explicit allowlist before navigating. For in-app navigation, use `router.navigateByUrl()` with a path.',
      example: {
        unsafe: `const returnUrl = this.route.snapshot.queryParamMap.get('returnUrl') ?? '/';
window.location.href = returnUrl;`,
        safe: `const returnUrl = this.route.snapshot.queryParamMap.get('returnUrl') ?? '/';
const target = new URL(returnUrl, location.origin);
if (target.origin === location.origin) {
  this.router.navigateByUrl(target.pathname + target.search);
}`,
      },
      references: [{ title: 'OWASP Unvalidated Redirects and Forwards', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html' }],
    },
  },
  analyze(ctx) {
    const findings: RuleFinding[] = [];
    for (const sink of navigationSinks(ctx)) {
      if (pinnedDestination(constantPrefix(ctx, sink.value))) continue;
      const result = ctx.taint.trace(sink.value, { context: 'url' });
      const flow = result.flows[0];
      if (!flow) continue;
      const v = urlValidation(ctx, sink.node, valueNames(ctx, sink.value, result.names));
      if (v.host === 'strong') continue;
      const confidence = v.host === 'custom' ? 'low' : v.host === 'weak' ? minConfidence(flow.confidence, 'medium') : flow.confidence;
      findings.push({
        node: sink.node,
        message: v.host === 'weak'
          ? `Untrusted data (${flow.source.description}) controls a ${sink.description} destination; the existing check is bypassable.`
          : `Untrusted data (${flow.source.description}) controls a ${sink.description} destination without validating its origin (open redirect).`,
        confidence,
        evidenceKind: 'dataflow',
        trace: [...flow.steps, sinkStep(ctx, sink.node, `${sink.description} navigates to the value`)],
        evidence: [...flowEvidence(flow), ...v.evidence.map((e) => `guard: ${e}`)],
      });
    }
    return findings;
  },
});
