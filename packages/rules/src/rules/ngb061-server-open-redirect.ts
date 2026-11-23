import type * as ts from 'typescript';
import { defineRule, minConfidence, type AnalysisContext, type RuleFinding } from '@ngbastion/plugin-api';
import { constantPrefix, flowEvidence, memberName, sinkStep, strip } from '../shared/common.js';
import { objectProp } from '../shared/http.js';
import { responseCall } from '../shared/server.js';
import { urlValidation, valueNames } from '../shared/url-guards.js';
import { pinnedDestination } from './ngb011-untrusted-redirect.js';

interface RedirectSink {
  node: ts.Node;
  value: ts.Expression;
  what: string;
}

/** `res.redirect([status,] url)`, `res.location(url)`, `res.setHeader/set/header('Location', url)`, `res.writeHead(3xx, { Location: url })`. */
function redirectSinks(ctx: AnalysisContext): RedirectSink[] {
  const out: RedirectSink[] = [];
  for (const call of ctx.index.calls) {
    const a = call.arguments;
    const name = memberName(ctx, strip(ctx, call.expression));
    if (!name || !a[0]) continue;
    if (name === 'redirect' && responseCall(ctx, call, ['redirect'])) {
      const url = a.length > 1 ? a[1]! : a[0];
      out.push({ node: call, value: url, what: 'res.redirect()' });
    } else if (name === 'location' && responseCall(ctx, call, ['location'])) {
      out.push({ node: call, value: a[0], what: 'res.location()' });
    } else if (['setHeader', 'set', 'header', 'append'].includes(name) && a[1] && /^location$/i.test(ctx.symbols.constantString(a[0]) ?? '') && responseCall(ctx, call, [name])) {
      out.push({ node: call, value: a[1], what: `res.${name}('Location')` });
    } else if (name === 'writeHead' && responseCall(ctx, call, ['writeHead'])) {
      const headers = a.find((x, i) => i > 0 && ctx.ts.isObjectLiteralExpression(strip(ctx, x)));
      const loc = objectProp(ctx, headers, 'Location') ?? objectProp(ctx, headers, 'location');
      if (loc) out.push({ node: call, value: loc, what: 'res.writeHead(…, { Location })' });
    }
  }
  return out;
}

export const ngb061 = defineRule({
  meta: {
    id: 'NGB061',
    name: 'Server-side open redirect',
    category: 'ssr',
    defaultSeverity: 'medium',
    cwe: ['CWE-601'],
    docs: {
      description:
        "Traces data from the incoming request (query string, route parameters, body, cookies) into redirects issued by SSR / Express server code: `res.redirect()`, `res.location()`, `Location` response headers. Redirect targets pinned to a path of this application (`'/account/' + id`) or a fixed origin, and targets checked against an allowlist or same-origin test before the redirect, are not reported. Client-controlled `Host` / `X-Forwarded-*` headers are reported by NGB042 instead.",
      rationale:
        "`/login?next=https://evil.example` that ends in `res.redirect(req.query.next)` turns your domain into a trusted-looking link to a phishing page, and in OAuth / SSO flows it can leak authorization codes or tokens to the attacker. Server redirects are invisible to browser-side checks such as NGB011.",
      patterns: [
        '`res.redirect(url)` / `res.redirect(302, url)` and `res.location(url)` on Express responses (also untyped `(req, res)` handlers)',
        "`res.setHeader('Location', url)`, `res.set/header/append('Location', url)`, `res.writeHead(302, { Location: url })` on Express / Node responses",
        'Sources: `req.query`, `req.params`, `req.body`, `req.path`, `req.url`, `req.originalUrl`, `req.cookies`',
        'Not reported: a constant prefix that pins the destination (`/app/…`, `https://host/…`); dominating same-origin / allowlist / relative-path checks (as NGB011)',
      ],
      limitations: [
        'Validation in a separate function or middleware that runs before the handler is not seen; a project validator used as a guard lowers confidence to low.',
        'Redirect helpers of other server frameworks (Fastify `reply.redirect`, Nest `@Redirect`) are not modeled.',
      ],
      falsePositives: [
        'A reverse proxy that rewrites or blocks external `Location` headers makes the finding unexploitable; document an exception naming that control.',
      ],
      remediation:
        "Redirect only to relative paths of your application or to an allowlist of origins: parse with `new URL(next, 'https://app.example')`, require `url.origin === 'https://app.example'` (or a path that starts with `/` but not `//` or `/\\`), and fall back to a default page otherwise.",
      example: {
        unsafe: `app.get('/login/done', (req, res) => res.redirect(String(req.query.next)));`,
        safe: `app.get('/login/done', (req, res) => {
  const next = String(req.query.next ?? '/');
  res.redirect(next.startsWith('/') && !next.startsWith('//') && !next.startsWith('/\\\\') ? next : '/');
});`,
      },
      references: [
        { title: 'OWASP — Unvalidated Redirects and Forwards Cheat Sheet', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html' },
        { title: 'Express — res.redirect()', url: 'https://expressjs.com/en/api.html#res.redirect' },
      ],
    },
  },
  analyze(ctx) {
    const findings: RuleFinding[] = [];
    for (const s of redirectSinks(ctx)) {
      if (pinnedDestination(constantPrefix(ctx, s.value))) continue;
      const result = ctx.taint.trace(s.value, { context: 'url' });
      const flow = result.flows.find((f) => f.source.kind !== 'request-header');
      if (!flow) continue;
      const v = urlValidation(ctx, s.node, valueNames(ctx, s.value, result.names));
      if (v.host === 'strong') continue;
      findings.push({
        node: s.node,
        message: v.host === 'weak'
          ? `${s.what} sends the client to ${flow.source.description}; the existing check is bypassable (open redirect).`
          : `${s.what} sends the client to ${flow.source.description} without validating the destination (open redirect).`,
        confidence: v.host === 'custom' ? 'low' : v.host === 'weak' ? minConfidence(flow.confidence, 'medium') : flow.confidence,
        evidenceKind: 'dataflow',
        trace: [...flow.steps, sinkStep(ctx, s.node, `${s.what} redirects to the value`)],
        evidence: [...flowEvidence(flow), ...v.evidence.map((e) => `guard: ${e}`)],
      });
    }
    return findings;
  },
});
