import type * as ts from 'typescript';
import { defineRule, type AnalysisContext, type RuleFinding } from '@ngbastion/plugin-api';
import { memberName, receiverOf, strip } from '../shared/common.js';
import { hostingHeaders } from '../shared/files.js';
import { objectLiteral, objectProp } from '../shared/http.js';
import { isServerResponse, moduleCall, requestHeaderRead } from '../shared/server.js';

const ALLOWLIST_CHECK = /\.(includes|has|indexOf|test|some|find|match|startsWith|endsWith)\(|===|!==|==|!=/;

/** `req.headers.origin`, or a local variable initialized from it. */
function originRead(ctx: AnalysisContext, e: ts.Expression): ts.Identifier | 'direct' | undefined {
  const t = ctx.ts;
  const x = strip(ctx, e);
  if (requestHeaderRead(ctx, x, ['origin'])) return 'direct';
  if (t.isIdentifier(x)) {
    const d = ctx.symbols.declarationOf(x);
    if (d && t.isVariableDeclaration(d) && d.initializer && requestHeaderRead(ctx, strip(ctx, d.initializer), ['origin'])) return x;
    // const { origin } = req.headers
    if (d && t.isBindingElement(d) && t.isVariableDeclaration(d.parent.parent) && d.parent.parent.initializer) {
      const key = d.propertyName && t.isIdentifier(d.propertyName) ? d.propertyName.text : t.isIdentifier(d.name) ? d.name.text : '';
      const init = strip(ctx, d.parent.parent.initializer);
      if (key.toLowerCase() === 'origin' && memberName(ctx, init) === 'headers') return x;
    }
  }
  return undefined;
}

/** `res.setHeader/set/header/append('<name>', value)` → [name, value]. */
function headerSet(ctx: AnalysisContext, call: ts.CallExpression): [string, ts.Expression] | undefined {
  const m = memberName(ctx, call.expression);
  if (!m || !['setHeader', 'set', 'header', 'append'].includes(m)) return undefined;
  const recv = receiverOf(ctx, strip(ctx, call.expression));
  const [k, v] = call.arguments;
  if (!recv || !k || !v || !isServerResponse(ctx, recv)) return undefined;
  const name = ctx.symbols.constantString(k)?.toLowerCase();
  return name ? [name, v] : undefined;
}

/** cors-style option objects: `cors({…})`, `app.enableCors({…})`, `fastify.register(fastifyCors, {…})`. */
function corsOptions(ctx: AnalysisContext, call: ts.CallExpression): ts.ObjectLiteralExpression | undefined {
  const t = ctx.ts;
  const callee = strip(ctx, call.expression);
  const name = t.isIdentifier(callee) ? callee.text : memberName(ctx, callee);
  if (moduleCall(ctx, call, ['cors'], ['cors', 'default', name ?? '']) || name === 'enableCors') return objectLiteral(ctx, call.arguments[0]);
  if (name === 'register' && call.arguments[0] && /cors/i.test(call.arguments[0].getText())) return objectLiteral(ctx, call.arguments[1]);
  return undefined;
}

/** `origin` option that allows every requesting origin: `true`, a callback that always allows, or the request's Origin header. */
function reflectsAnyOrigin(ctx: AnalysisContext, origin: ts.Expression): string | undefined {
  const t = ctx.ts;
  const o = strip(ctx, origin);
  if (o.kind === t.SyntaxKind.TrueKeyword) return 'origin: true reflects every requesting origin';
  if (originRead(ctx, o)) return 'origin is set from the request Origin header';
  if ((t.isArrowFunction(o) || t.isFunctionExpression(o)) && o.parameters.length >= 2) {
    const cb = o.parameters[1]!.name;
    if (!t.isIdentifier(cb)) return undefined;
    let allowsAll = false;
    let guarded = false;
    const visit = (n: ts.Node): void => {
      if (t.isIfStatement(n) || t.isConditionalExpression(n) || (t.isBinaryExpression(n) && /^[!=]==?$/.test(n.operatorToken.getText()))) guarded = true;
      if (t.isCallExpression(n) && t.isIdentifier(n.expression) && n.expression.text === cb.text && n.arguments[1]) {
        const v = strip(ctx, n.arguments[1]);
        if (v.kind === t.SyntaxKind.TrueKeyword || (t.isIdentifier(v) && t.isIdentifier(o.parameters[0]!.name) && v.text === o.parameters[0]!.name.text)) allowsAll = true;
        else guarded = true;
      }
      if (t.isCallExpression(n) && ALLOWLIST_CHECK.test(n.expression.getText() + '(')) guarded = true;
      t.forEachChild(n, visit);
    };
    visit(o.body);
    if (allowsAll && !guarded) return 'the origin callback allows every origin';
  }
  return undefined;
}

export const ngb081 = defineRule({
  meta: {
    id: 'NGB081',
    name: 'Permissive CORS with credentials',
    category: 'ssr',
    defaultSeverity: 'high',
    cwe: ['CWE-942', 'CWE-346'],
    docs: {
      description:
        "Reports server code and hosting configuration that let any website make credentialed cross-origin requests and read the responses: `Access-Control-Allow-Origin` set from the request's `Origin` header without an allowlist check, `cors({ origin: true, credentials: true })` (also `enableCors` / `register(fastifyCors, …)`) or an origin callback that always allows, combined with `Access-Control-Allow-Credentials: true` — and `Access-Control-Allow-Origin: null` with credentials.",
      rationale:
        "With credentials allowed, the browser attaches the victim's cookies to the cross-origin request and lets the requesting page read the response. Reflecting the caller's Origin (or allowing `null`, which sandboxed iframes and `data:` pages send) therefore lets any malicious website read every authenticated API response of a logged-in user — profile data, CSRF tokens, payment details — and act on their behalf.",
      patterns: [
        "`res.setHeader('Access-Control-Allow-Origin', req.headers.origin)` (also `res.set/header/append`, `req.get('origin')`, a local variable holding it) together with `Access-Control-Allow-Credentials: true` in the same function — not reported when a dominating condition checks the origin (`ALLOWED.includes(origin)`, `origin === …`, regex test)",
        '`cors({ origin: true, credentials: true })`, `{ origin: (origin, cb) => cb(null, true), credentials: true }`, `app.enableCors({ … })`, `fastify.register(cors, { … })`',
        "`Access-Control-Allow-Origin: null` with `Access-Control-Allow-Credentials: true` in server code or hosting configs (`firebase.json`, `vercel.json`, `staticwebapp.config.json`, `_headers`)",
      ],
      limitations: [
        "`Access-Control-Allow-Origin: *` with credentials is not reported: browsers refuse that combination, so it fails closed.",
        'Allowlist checks in other functions (CORS middleware factories, config objects) are not seen; reflection guarded only elsewhere is reported.',
        'Reflection without `Access-Control-Allow-Credentials: true` is not reported (it is equivalent to `*`).',
      ],
      falsePositives: [
        'APIs that intentionally serve any origin with cookies but expose only public data are reported; drop `credentials` for them.',
      ],
      remediation:
        "Allow credentials only for an explicit list of trusted origins: `cors({ origin: ['https://app.example.com'], credentials: true })`, or check `ALLOWED_ORIGINS.includes(origin)` before echoing it (and add `Vary: Origin`). Never allow `null`.",
      example: {
        unsafe: "app.use(cors({ origin: true, credentials: true }));",
        safe: "app.use(cors({ origin: ['https://app.example.com'], credentials: true }));",
      },
      references: [
        { title: 'PortSwigger — CORS vulnerabilities', url: 'https://portswigger.net/web-security/cors' },
        { title: 'MDN — Access-Control-Allow-Credentials', url: 'https://developer.mozilla.org/docs/Web/HTTP/Headers/Access-Control-Allow-Credentials' },
      ],
    },
  },
  analyze(ctx) {
    const t = ctx.ts;
    const findings: RuleFinding[] = [];
    const credentialFns = new Set<ts.Node>();
    const origins: { call: ts.CallExpression; value: ts.Expression; fn: ts.Node }[] = [];
    for (const call of ctx.index.calls) {
      const h = headerSet(ctx, call);
      if (h) {
        const fn = ctx.flow.enclosingFunction(call) ?? call.getSourceFile();
        if (h[0] === 'access-control-allow-credentials' && ctx.symbols.constantString(h[1])?.trim() === 'true') credentialFns.add(fn);
        if (h[0] === 'access-control-allow-origin') origins.push({ call, value: h[1], fn });
        continue;
      }
      const opts = corsOptions(ctx, call);
      if (!opts) continue;
      const cred = objectProp(ctx, opts, 'credentials');
      const origin = objectProp(ctx, opts, 'origin');
      if (!cred || strip(ctx, cred).kind !== t.SyntaxKind.TrueKeyword || !origin) continue;
      const why = reflectsAnyOrigin(ctx, origin) ?? (ctx.symbols.constantString(origin) === 'null' ? "origin 'null' is allowed" : undefined);
      if (!why) continue;
      findings.push({ node: call, message: `CORS allows credentialed requests from any website (${why}); a malicious page can read authenticated responses of logged-in users.`, confidence: 'high', evidenceKind: 'pattern', evidence: [why, 'credentials: true'] });
    }
    for (const o of origins) {
      if (!credentialFns.has(o.fn)) continue;
      const constant = ctx.symbols.constantString(o.value);
      const read = originRead(ctx, o.value);
      if (constant?.trim() === 'null') {
        findings.push({ node: o.call, message: "Access-Control-Allow-Origin: null with credentials lets sandboxed iframes and data: pages on any site read authenticated responses.", confidence: 'high', evidenceKind: 'pattern', evidence: ['Access-Control-Allow-Origin: null', 'Access-Control-Allow-Credentials: true'] });
        continue;
      }
      if (!read) continue;
      const name = read === 'direct' ? undefined : read.text;
      const guarded = ctx.flow.guards(o.call).some((g) => {
        const text = g.condition.getText();
        return ALLOWLIST_CHECK.test(text) && (/origin/i.test(text) || (!!name && text.includes(name)));
      });
      if (guarded) continue;
      findings.push({ node: o.call, message: "Access-Control-Allow-Origin echoes the request's Origin header with credentials allowed; any website can read authenticated responses of logged-in users.", confidence: 'high', evidenceKind: 'pattern', evidence: ['Access-Control-Allow-Origin ← request Origin header (no allowlist check in this function)', 'Access-Control-Allow-Credentials: true'] });
    }
    const nullOrigin = hostingHeaders(ctx, 'Access-Control-Allow-Origin').filter((h) => h.value.trim() === 'null');
    const credOrigins = new Set(hostingHeaders(ctx, 'Access-Control-Allow-Credentials').filter((h) => h.value.trim() === 'true').map((h) => h.origin));
    for (const h of nullOrigin) {
      if (!credOrigins.has(h.origin)) continue;
      findings.push({ location: h.location, message: `${h.origin} sends Access-Control-Allow-Origin: null with credentials; sandboxed iframes and data: pages on any site can read authenticated responses.`, confidence: 'high', evidenceKind: 'pattern', evidence: ['Access-Control-Allow-Origin: null', 'Access-Control-Allow-Credentials: true'] });
    }
    return findings;
  },
});
