import type * as ts from 'typescript';
import { defineRule, lowerConfidence, type AnalysisContext, type RuleFinding, type Severity, type TaintFlow } from '@ngbastion/plugin-api';
import { flowEvidence, hasFixedOrigin, sinkStep } from '../shared/common.js';
import { authSignals } from '../shared/auth.js';
import { requestCalls, urlParts, type RequestCall } from '../shared/http.js';
import { sensitiveValue } from '../shared/sensitivity.js';
import { urlValidation, valueNames } from '../shared/url-guards.js';

/** Sources an attacker controls for another user's browser. */
const ATTACKER = new Set(['url', 'message', 'window-name', 'referrer']);
const MUTATING = new Set(['post', 'put', 'patch', 'delete']);

type Position = 'origin' | 'path';

/** Where the first attacker-controlled part sits in the URL. */
function taintedPart(ctx: AnalysisContext, r: RequestCall): { flow: TaintFlow; position: Position; expr: ts.Expression; prefix: string } | undefined {
  const parts = urlParts(ctx, r.url);
  let prefix = '';
  let dynamicBase = false;
  for (const p of parts) {
    if (p.text !== undefined) {
      prefix += p.text;
      continue;
    }
    if (/[?#]/.test(prefix)) return undefined; // query / fragment values do not choose the destination
    const result = ctx.taint.trace(p.expr, { context: 'url' });
    const flow = result.flows.find((f) => ATTACKER.has(f.source.kind));
    if (!flow) {
      dynamicBase = true;
      prefix += '\uE000';
      continue;
    }
    const fixed = dynamicBase || hasFixedOrigin(prefix)
      || (prefix.length > 1 && prefix[0] === '/' && prefix[1] !== '/' && prefix[1] !== '\\')
      || (prefix.length > 0 && !/^[a-z][a-z0-9+.-]*:/i.test(prefix) && !/^[/\\]/.test(prefix) && /\//.test(prefix));
    return { flow, position: fixed ? 'path' : 'origin', expr: p.expr, prefix };
  }
  return undefined;
}

/** A dominating `/^…$/.test(x)` or `.match()` guard on a traced name counts as validation of a path segment. */
function regexGuarded(ctx: AnalysisContext, node: ts.Node, names: Set<string>): boolean {
  return ctx.flow.guards(node).some((g) => /\/\^[^/]*\$\/[gimsuy]*\.test\(|\.match\(\/\^/.test(g.condition.getText()) && [...names].some((n) => g.condition.getText().includes(n)));
}

export const ngb026 = defineRule({
  meta: {
    id: 'NGB026',
    name: 'Untrusted HTTP request destination',
    category: 'navigation-auth',
    defaultSeverity: 'high',
    cwe: ['CWE-918', 'CWE-22', 'CWE-352'],
    docs: {
      description:
        "Traces attacker-controllable values (URL / route parameters, postMessage data, `window.name`, `document.referrer`) into the URL of outgoing requests — `HttpClient` methods, `fetch()`, `XMLHttpRequest.open()`, `navigator.sendBeacon()`, `EventSource`, `WebSocket`. When the value can choose the destination origin, requests (and any credentials or sensitive body attached to them) go to the attacker. When the origin is fixed but the value forms a path segment, the attacker can redirect the victim's authenticated request to another endpoint of your API (client-side path traversal / request forgery).",
      rationale:
        "Angular decodes route parameters, so `/items/..%2F..%2Fadmin%2Fusers%2F42` turns `this.http.delete(`/api/items/${id}`)` into `DELETE /api/admin/users/42` sent with the victim's cookies or token. When the whole URL comes from a query parameter, an `Authorization` header added to the request, a credentialed body or the response handling (rendering, redirects) is under attacker control.",
      patterns: [
        'Requests: `HttpClient.get/post/put/patch/delete/head/options/request/jsonp`, `fetch(url, init)`, `xhr.open(method, url)`, `navigator.sendBeacon(url)`, `new EventSource(url)`, `new WebSocket(url)`, RxJS `webSocket(url)`',
        'URL decomposition: template literals, `+` concatenation and `const` URL variables; values after `?` or `#` are not destinations and are ignored',
        'Origin control (high severity with an auth header, credentials or a sensitive body; otherwise medium): the attacker value is first, or follows only a scheme / `/`',
        'Path control: a fixed `https://host/`, `/api/…`, relative `api/…` or configured base (`environment.apiUrl`) precedes the value — medium severity for state-changing methods (POST/PUT/PATCH/DELETE), low for reads',
        'Recognized validation: `encodeURIComponent()` and numeric conversion on the value, host allowlists / same-origin checks (as NGB011) for origin control, anchored regex tests (`/^[\\w-]+$/.test(id)`) for path segments',
      ],
      limitations: [
        "`encodeURIComponent('..')` is still `..`; a single path level can be traversed after encoding. This is accepted as mitigation (one segment can no longer inject `/`).",
        'Values from HTTP responses, Web Storage and form inputs are not treated as attacker-controlled here (users control their own inputs; response-driven URLs are usually API links).',
        "Whether the server would accept the forged request (method, CSRF token, authorization) is not visible.",
      ],
      falsePositives: [
        'Read-only lookups by route ID (`GET /api/items/${id}`) are low severity and low confidence; they are hidden by the default `minConfidence: medium`.',
      ],
      remediation:
        "Validate identifiers before using them in a request path (`/^[A-Za-z0-9_-]+$/`, numeric conversion) and encode them with `encodeURIComponent()`. Never take a complete request URL or host from URL parameters or messages; map allowed values to fixed endpoints instead.",
      example: {
        unsafe: `const id = this.route.snapshot.paramMap.get('id');
this.http.delete(\`/api/projects/\${id}\`).subscribe();`,
        safe: `const id = this.route.snapshot.paramMap.get('id') ?? '';
if (!/^[0-9a-f-]{36}$/.test(id)) return;
this.http.delete(\`/api/projects/\${encodeURIComponent(id)}\`).subscribe();`,
      },
      references: [
        { title: 'OWASP — Client-Side Path Traversal (CSPT)', url: 'https://owasp.org/www-community/attacks/Path_Traversal' },
        { title: 'OWASP — Server-Side Request Forgery Prevention', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html' },
      ],
    },
  },
  analyze(ctx) {
    const findings: RuleFinding[] = [];
    const signals = authSignals(ctx);
    for (const r of requestCalls(ctx)) {
      const hit = taintedPart(ctx, r);
      if (!hit) continue;
      const names = valueNames(ctx, hit.expr, hit.flow.steps.map((s) => s.symbol ?? '').filter(Boolean));
      const evidence = [...flowEvidence(hit.flow), `URL prefix before the value: ${hit.prefix ? JSON.stringify(hit.prefix.replace(/\uE000/g, '${…}')) : '(none)'}`];
      let severity: Severity;
      let confidence = hit.flow.confidence;
      let message: string;
      if (hit.position === 'origin') {
        const v = urlValidation(ctx, r.node, names);
        if (v.host === 'strong') continue;
        if (v.host) confidence = lowerConfidence(confidence);
        const body = r.body ? sensitiveValue(ctx, r.body) : undefined;
        const carries = [
          ...(r.authHeader ? ['an Authorization/API-key header'] : []),
          ...(r.credentials ? ['credentials (cookies)'] : []),
          ...(body ? ['a sensitive request body'] : []),
        ];
        const viaInterceptor = r.api.startsWith('HttpClient') && signals.bearerHeaders.length > 0;
        severity = carries.length || viaInterceptor ? 'high' : 'medium';
        message = `${r.api} sends a request to a destination chosen by ${hit.flow.source.description}${carries.length ? ` together with ${carries.join(' and ')}` : ''}; an attacker can point it at their own server.`;
        evidence.push(...(v.evidence.length ? v.evidence.map((e) => `validation: ${e}`) : []), ...(viaInterceptor && !carries.length ? ['the application attaches Authorization headers to HttpClient requests (interceptor)'] : []), ...(body?.evidence ?? []));
      } else {
        if (regexGuarded(ctx, r.node, names)) continue;
        const mutating = !!r.method && MUTATING.has(r.method);
        severity = mutating ? 'medium' : 'low';
        if (!mutating) confidence = lowerConfidence(confidence);
        message = `${r.api} builds its request path from ${hit.flow.source.description} without validating it; values such as '../' redirect this ${r.method ? r.method.toUpperCase() + ' ' : ''}request to other endpoints with the user's credentials (client-side path traversal).`;
      }
      findings.push({
        node: r.node,
        message,
        confidence,
        severity,
        evidenceKind: 'dataflow',
        trace: [...hit.flow.steps, sinkStep(ctx, r.node, `${r.api} URL`)],
        evidence,
      });
    }
    return findings;
  },
});
