import type * as ts from 'typescript';
import { defineRule, type AnalysisContext, type RuleFinding } from '@ngbastion/plugin-api';
import { flowEvidence, memberName, receiverOf, sinkStep, strip } from '../shared/common.js';
import { responseCall } from '../shared/server.js';

/** Escaping helpers commonly used before writing HTML (escape-html, he, lodash, validator, entities). */
const ESCAPE = /^(escape(Html|HTML|Xml)?|encode(Html|HTML|XML)?|htmlEscape|sanitize(Html)?|purify|xss|filterXSS|encodeHTML)$/;
const NON_HTML_TYPE = /json|javascript|text\/plain|text\/csv|octet-stream|image\/|application\/(?!xhtml)/i;

/** Content type set on the response earlier in the same function or in the call chain. */
function declaresNonHtml(ctx: AnalysisContext, call: ts.CallExpression): boolean {
  const t = ctx.ts;
  // res.type('json').send(x) / res.set('Content-Type', 'text/plain').send(x)
  for (let r = receiverOf(ctx, strip(ctx, call.expression)); r && t.isCallExpression(strip(ctx, r)); r = receiverOf(ctx, (strip(ctx, r) as ts.CallExpression).expression)) {
    if (contentTypeCall(ctx, strip(ctx, r) as ts.CallExpression)) return true;
  }
  const fn = ctx.flow.enclosingFunction(call);
  if (!fn) return false;
  let found = false;
  const visit = (n: ts.Node): void => {
    if (found || n.pos > call.pos) return;
    if (t.isCallExpression(n) && contentTypeCall(ctx, n)) found = true;
    t.forEachChild(n, visit);
  };
  visit(fn);
  return found;
}

function contentTypeCall(ctx: AnalysisContext, c: ts.CallExpression): boolean {
  const name = memberName(ctx, strip(ctx, c.expression));
  const [a, b] = c.arguments;
  if (!a) return false;
  if (name === 'type' || name === 'contentType') return NON_HTML_TYPE.test(ctx.symbols.constantString(a) ?? '') || /^(json|txt|text|csv|js)$/.test(ctx.symbols.constantString(a) ?? '');
  if ((name === 'setHeader' || name === 'set' || name === 'header') && b) return /^content-type$/i.test(ctx.symbols.constantString(a) ?? '') && NON_HTML_TYPE.test(ctx.symbols.constantString(b) ?? '');
  if (name === 'writeHead') return c.arguments.some((x) => /content-type['"]?\s*:\s*['"][^'"]*(json|plain|javascript|csv)/i.test(x.getText()));
  return false;
}

/** The value is an object / array / number (serialized as JSON or rejected by Express), not a string. */
function nonString(ctx: AnalysisContext, e: ts.Expression): boolean {
  const t = ctx.ts;
  const x = strip(ctx, e);
  if (t.isObjectLiteralExpression(x) || t.isArrayLiteralExpression(x) || t.isNumericLiteral(x)) return true;
  const type = ctx.checker.getTypeAtLocation(x);
  if (type.flags & (t.TypeFlags.Any | t.TypeFlags.Unknown)) return false;
  return !ctx.checker.isTypeAssignableTo(ctx.checker.getStringType(), type) && !(type.flags & t.TypeFlags.StringLike);
}

export const ngb069 = defineRule({
  meta: {
    id: 'NGB069',
    name: 'Reflected XSS in server responses',
    category: 'ssr',
    defaultSeverity: 'high',
    cwe: ['CWE-79'],
    docs: {
      description:
        "Traces request data (query string, route parameters, body, cookies, path) into raw response bodies written by Express / Node server code — `res.send()`, `res.write()`, `res.end()` — when the response is HTML (Express sends strings as `text/html` by default). Responses that declare a non-HTML content type (`res.type('json')`, `Content-Type: text/plain`), JSON responses (`res.json()`, objects), and values passed through an HTML escaping function (`escape-html`, `he.encode`, `_.escape`, DOMPurify) are not reported. Rendering through Angular SSR is not affected: Angular escapes interpolations.",
      rationale:
        "Server routes next to the Angular SSR engine — error pages, OAuth callbacks, health and preview endpoints — often build HTML by string concatenation. `res.send(`<p>No results for ${req.query.q}</p>`)` executes any `<script>` the attacker places in the link in your origin, with access to cookies that are not HttpOnly, session storage, and every API the user can call. The Angular sanitizer never sees these responses.",
      patterns: [
        '`res.send(v)`, `res.write(v)`, `res.end(v)` on Express / Node responses (also `res.status(400).send(v)` chains and untyped `(req, res)` handlers)',
        'Sources: `req.query`, `req.params`, `req.body`, `req.path`, `req.url`, `req.originalUrl`, `req.cookies`',
        'Not reported: `res.json()`, non-string values, responses with a non-HTML `Content-Type` set in the chain or earlier in the handler, values passed through an escaping function',
      ],
      limitations: [
        'Content types set by middleware or in another function are not seen; such responses may be reported although they are not HTML.',
        'Template engines (`res.render()`) are not analyzed here; server-side template injection is NGB079.',
      ],
      falsePositives: [
        'Responses served with `X-Content-Type-Options: nosniff` and a non-HTML type set elsewhere are not exploitable; set the type in the handler to make it visible.',
      ],
      remediation:
        "Return data as JSON (`res.json({ q })`) and render it client-side, or escape every request-derived value for HTML (`escapeHtml(q)` from `escape-html`) before building markup. Set an explicit `Content-Type` and a restrictive CSP on server-generated pages.",
      example: {
        unsafe: 'app.get(\'/search\', (req, res) => res.send(`<p>No results for ${req.query.q}</p>`));',
        safe: "import escapeHtml from 'escape-html';\napp.get('/search', (req, res) => res.send(`<p>No results for ${escapeHtml(String(req.query.q))}</p>`));",
      },
      references: [
        { title: 'OWASP — Cross Site Scripting Prevention Cheat Sheet', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html' },
        { title: 'Express — res.send() content types', url: 'https://expressjs.com/en/api.html#res.send' },
      ],
    },
  },
  analyze(ctx) {
    const findings: RuleFinding[] = [];
    for (const call of ctx.index.calls) {
      const value = call.arguments[0];
      if (!value || !responseCall(ctx, call, ['send', 'write', 'end'])) continue;
      if (nonString(ctx, value) || declaresNonHtml(ctx, call)) continue;
      const result = ctx.taint.trace(value, { context: 'html' });
      const escaped = escapedSources(ctx, value);
      const flow = result.flows.find((f) => f.source.kind !== 'request-header' && !escaped.has(key(f.source.location)));
      if (!flow) continue;
      const method = memberName(ctx, strip(ctx, call.expression));
      findings.push({
        node: call,
        message: `res.${method}() writes ${flow.source.description} into an HTML response without escaping (reflected XSS).`,
        confidence: flow.confidence,
        evidenceKind: 'dataflow',
        trace: [...flow.steps, sinkStep(ctx, call, `res.${method}() writes the value into the response body`)],
        evidence: [...flowEvidence(flow), 'response content type: text/html (Express default for strings) or not declared'],
      });
    }
    return findings;
  },
});

/** Source locations that reach the value only through an escaping call inside it (`escapeHtml(q)`). */
function escapedSources(ctx: AnalysisContext, value: ts.Expression): Set<string> {
  const t = ctx.ts;
  const out = new Set<string>();
  const visit = (n: ts.Node): void => {
    if (t.isCallExpression(n) && n.arguments[0]) {
      const callee = strip(ctx, n.expression);
      const name = t.isIdentifier(callee) ? callee.text : memberName(ctx, callee) ?? '';
      if (ESCAPE.test(name)) {
        for (const f of ctx.taint.trace(n.arguments[0], { context: 'generic' }).flows) out.add(key(f.source.location));
        return;
      }
    }
    t.forEachChild(n, visit);
  };
  visit(value);
  return out;
}

const key = (l: { file: string; line: number; column: number }) => `${l.file}:${l.line}:${l.column}`;
