import type * as ts from 'typescript';
import { defineRule, type AnalysisContext, type RuleFinding, type Severity, type TaintFlow } from '@ngbastion/plugin-api';
import { codeFiles, flowEvidence, is, memberName, receiverOf, sinkStep, strip } from '../shared/common.js';
import { requestCalls } from '../shared/http.js';

/** A dominating allowlist / equality check on a header-derived value. */
function validated(ctx: AnalysisContext, node: ts.Node, flow: TaintFlow): boolean {
  const names = flow.steps.map((s) => s.symbol).filter((x): x is string => !!x);
  return ctx.flow.guards(node).some((g) => {
    const c = g.condition.getText();
    return /\b(includes|has|indexOf)\(|[!=]==/.test(c) && (names.some((n) => c.includes(n)) || /host|origin|forwarded/i.test(c));
  });
}

interface Sink {
  node: ts.Node;
  value: ts.Expression;
  what: string;
  severity: Severity;
}

function sinks(ctx: AnalysisContext): Sink[] {
  const t = ctx.ts;
  const out: Sink[] = [];
  for (const r of requestCalls(ctx)) out.push({ node: r.node, value: r.url, what: `${r.api} URL (server-side request forgery)`, severity: 'high' });
  for (const call of ctx.index.calls) {
    const name = memberName(ctx, strip(ctx, call.expression));
    const a = call.arguments;
    if (!name || !a[0]) continue;
    if (name === 'redirect') out.push({ node: call, value: a[a.length - 1]!, what: 'redirect Location', severity: 'medium' });
    else if (name === 'location' && receiverOf(ctx, strip(ctx, call.expression))) out.push({ node: call, value: a[0], what: 'Location header', severity: 'medium' });
    else if ((name === 'setHeader' || name === 'set' || name === 'header' || name === 'append') && a[1] && /^location$/i.test(ctx.symbols.constantString(a[0]) ?? '')) out.push({ node: call, value: a[1], what: 'Location header', severity: 'medium' });
    else if ((name === 'updateTag' || name === 'addTag') && is(ctx.symbols.callee(call)?.receiver, '@angular/platform-browser', 'Meta')) {
      const content = t.isObjectLiteralExpression(strip(ctx, a[0])) ? (strip(ctx, a[0]) as ts.ObjectLiteralExpression).properties.find((p): p is ts.PropertyAssignment => t.isPropertyAssignment(p) && p.name.getText() === 'content') : undefined;
      if (content) out.push({ node: call, value: content.initializer, what: 'meta tag URL (cache poisoning)', severity: 'medium' });
    } else if (name === 'setAttribute' && a[1] && /^(href|src|action|content)$/i.test(ctx.symbols.constantString(a[a.length - 2]!) ?? '')) {
      out.push({ node: call, value: a[a.length - 1]!, what: 'rendered link URL (cache poisoning)', severity: 'medium' });
    }
  }
  // { provide: API_BASE_URL, useValue: `${proto}://${host}` } — every HttpClient call then targets the attacker.
  for (const sf of codeFiles(ctx)) {
    const visit = (n: ts.Node): void => {
      if (t.isPropertyAssignment(n) && n.name.getText() === 'useValue' && t.isObjectLiteralExpression(n.parent)
        && n.parent.properties.some((p) => t.isPropertyAssignment(p) && p.name.getText() === 'provide')) {
        out.push({ node: n, value: n.initializer, what: 'provider value (base URL for later requests)', severity: 'high' });
      }
      t.forEachChild(n, visit);
    };
    visit(sf);
  }
  return out;
}

export const ngb042 = defineRule({
  meta: {
    id: 'NGB042',
    name: 'Host header injection in SSR',
    category: 'ssr',
    defaultSeverity: 'high',
    cwe: ['CWE-644', 'CWE-918', 'CWE-601'],
    docs: {
      description:
        "Traces the client-controlled `Host`, `X-Forwarded-Host`, `X-Forwarded-Proto` and `Forwarded` request headers (Express `req.headers` / `req.get()` / `req.hostname` / `req.protocol`, Node `IncomingMessage`, and the Fetch `Request` from Angular's `REQUEST` token) into security-sensitive URLs built by server-side code: outgoing requests (SSRF), provider values used as API base URLs, redirects / `Location` headers, and URLs rendered into meta tags or links.",
      rationale:
        "The `Host` header is chosen by the client. SSR code that builds absolute URLs from it lets an attacker make the server call internal services or their own host (SSRF), poison cached pages with links to their domain, or redirect users elsewhere. Typical bug: `{ provide: BASE_URL, useValue: `${req.protocol}://${req.get('host')}` }` so every server-side `HttpClient` request — with forwarded cookies — goes to the attacker.",
      patterns: [
        "Sources: `req.headers.host`, `req.headers['x-forwarded-host']`, `req.get('host')`, `req.header('x-forwarded-proto')`, `req.hostname`, `req.host`, `req.protocol` (Express / Node request types), `request.headers.get('host')` (Fetch `Request` / `Headers`)",
        'Sinks: `HttpClient` / `fetch` request URLs (high), `{ provide: …, useValue: … }` provider values (high), `res.redirect()`, `res.location()`, `Location` headers, `Meta.updateTag/addTag({ content })`, `setAttribute("href" | "src" | "content", …)` (medium)',
        'Validation recognized: a dominating allowlist or equality check on the host value (`ALLOWED_HOSTS.includes(host)`, `host === CANONICAL_HOST`)',
      ],
      limitations: [
        "Proxy configuration (`app.set('trust proxy', …)`) and Angular's host allowlisting in the SSR engine (`allowedHosts`) are not evaluated; a finding may be unexploitable if the deployment already rejects unknown hosts.",
        'Headers copied into objects or services before use are followed only as far as the taint engine models the flow.',
      ],
      falsePositives: [
        'Deployments behind a proxy that overwrites `Host` with a fixed value are not exploitable; document an exception that names the proxy setting.',
      ],
      remediation:
        "Build absolute URLs from configuration (a constant canonical origin or an environment variable), not from request headers. If you need the request host, compare it against an allowlist first and enable Angular SSR's host allowlist for the server engine.",
      example: {
        unsafe: "providers: [{ provide: API_BASE_URL, useValue: `${req.protocol}://${req.get('host')}/api` }]",
        safe: "providers: [{ provide: API_BASE_URL, useValue: process.env['PUBLIC_ORIGIN'] + '/api' }]",
      },
      references: [
        { title: 'OWASP WSTG — Testing for Host Header Injection', url: 'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/17-Testing_for_Host_Header_Injection' },
        { title: 'PortSwigger — HTTP Host header attacks', url: 'https://portswigger.net/web-security/host-header' },
      ],
    },
  },
  analyze(ctx) {
    const findings: RuleFinding[] = [];
    for (const s of sinks(ctx)) {
      const result = ctx.taint.trace(s.value, { context: 'url' });
      const flow = result.flows.find((f) => f.source.kind === 'request-header');
      if (!flow || validated(ctx, s.node, flow)) continue;
      findings.push({
        node: s.node,
        message: `${s.what} is built from ${flow.source.description}, which the client controls; an attacker can point it at another host.`,
        confidence: flow.confidence,
        severity: s.severity,
        evidenceKind: 'dataflow',
        trace: [...flow.steps, sinkStep(ctx, s.node, s.what)],
        evidence: [...flowEvidence(flow), 'proxy / allowedHosts configuration: not assessed'],
      });
    }
    return findings;
  },
});
