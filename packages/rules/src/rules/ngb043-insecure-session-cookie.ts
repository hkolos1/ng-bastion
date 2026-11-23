import type * as ts from 'typescript';
import { defineRule, type AnalysisContext, type RuleFinding, type Severity } from '@ngbastion/plugin-api';
import { is, memberName, receiverOf, strip } from '../shared/common.js';
import { authCookieName } from '../shared/auth.js';
import { objectLiteral, objectProp, urlParts } from '../shared/http.js';
import { classifyName } from '../shared/sensitivity.js';

const RESPONSE_MODULES = ['express', 'express-serve-static-core', 'http', 'node:http'];

interface Attrs {
  httpOnly?: boolean;
  secure?: boolean;
  sameSite?: string;
  /** Option values that are not constant (cannot be assessed). */
  dynamic: string[];
}

function flag(ctx: AnalysisContext, e: ts.Expression | undefined, attrs: Attrs, key: string): boolean | undefined {
  if (!e) return undefined;
  const x = strip(ctx, e);
  if (x.kind === ctx.ts.SyntaxKind.TrueKeyword) return true;
  if (x.kind === ctx.ts.SyntaxKind.FalseKeyword) return false;
  attrs.dynamic.push(key);
  return undefined;
}

function fromOptions(ctx: AnalysisContext, opts: ts.Expression | undefined): Attrs {
  const attrs: Attrs = { dynamic: [] };
  const o = objectLiteral(ctx, opts);
  if (opts && !o) {
    attrs.dynamic.push('options');
    return attrs;
  }
  const httpOnly = flag(ctx, objectProp(ctx, o, 'httpOnly'), attrs, 'httpOnly');
  const secure = flag(ctx, objectProp(ctx, o, 'secure'), attrs, 'secure');
  const ss = objectProp(ctx, o, 'sameSite');
  const sameSite = ss ? (strip(ctx, ss).kind === ctx.ts.SyntaxKind.TrueKeyword ? 'strict' : ctx.symbols.constantString(ss)?.toLowerCase()) : undefined;
  return { ...attrs, ...(httpOnly !== undefined ? { httpOnly } : {}), ...(secure !== undefined ? { secure } : {}), ...(sameSite ? { sameSite } : {}) };
}

function fromHeader(text: string): Attrs {
  const lower = text.toLowerCase();
  const ss = /;\s*samesite=(\w+)/.exec(lower);
  return { httpOnly: /;\s*httponly\b/.test(lower), secure: /;\s*secure\b/.test(lower), ...(ss ? { sameSite: ss[1]! } : {}), dynamic: [] };
}

const sensitiveCookie = (name: string) => authCookieName(name) || classifyName(name)?.category === 'credential';

export const ngb043 = defineRule({
  meta: {
    id: 'NGB043',
    name: 'Insecure session cookie attributes',
    category: 'ssr',
    defaultSeverity: 'high',
    cwe: ['CWE-1004', 'CWE-614', 'CWE-1275'],
    docs: {
      description:
        "Reports session and authentication cookies issued by server code in the repository (Angular SSR `server.ts`, Express handlers, BFF endpoints) without `HttpOnly` (high), without `Secure` (medium), or with `SameSite=None` and no `Secure` (medium): Express `res.cookie(name, value, options)`, `Set-Cookie` headers set with `res.setHeader()` / `res.append()` / `headers.append()`, and `cookie.serialize()`.",
      rationale:
        "The server is the only place that can protect a session cookie. Without `HttpOnly`, any XSS payload reads the session with `document.cookie`; without `Secure`, it is sent over plain HTTP and can be captured; `SameSite=None` without `Secure` is rejected by modern browsers, so the intended cross-site flow silently breaks or teams fall back to weaker settings.",
      patterns: [
        "`res.cookie('session', id, { … })` on Express / Node response types",
        "`res.setHeader('Set-Cookie', 'sid=…; Path=/')`, `res.append('Set-Cookie', …)`, `headers.append('Set-Cookie', …)` with constant attribute text (template literals are split into constant parts)",
        "`cookie.serialize(name, value, options)` from the `cookie` package",
        'Cookie names: `session`, `sid`, `connect.sid`, `auth`, `token`, `jwt`, `access_token`, `refresh_token`, `remember_me` and names classified as credentials; CSRF/XSRF cookies are ignored (they must be readable by JavaScript)',
        'Options set to non-constant values (`secure: process.env.NODE_ENV === "production"`) are not reported for that attribute',
      ],
      limitations: [
        'Cookies set by frameworks or middleware (e.g. `express-session` configuration) are not analyzed.',
        'Cookie names that are not constant are not classified.',
      ],
      falsePositives: [
        'A `token` cookie that intentionally must be readable by client code (not a session credential) can be reported; rename it or document an exception.',
      ],
      remediation:
        "Issue session cookies as `{ httpOnly: true, secure: true, sameSite: 'lax' (or 'strict'), path: '/' }`, preferably with the `__Host-` prefix, and set them only over HTTPS.",
      example: {
        unsafe: `res.cookie('session', sessionId, { sameSite: 'none' });`,
        safe: `res.cookie('__Host-session', sessionId, { httpOnly: true, secure: true, sameSite: 'lax', path: '/' });`,
      },
      references: [
        { title: 'OWASP — Session Management Cheat Sheet (cookie attributes)', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#cookies' },
        { title: 'Express — res.cookie()', url: 'https://expressjs.com/en/api.html#res.cookie' },
      ],
    },
  },
  analyze(ctx) {
    const findings: RuleFinding[] = [];
    const report = (node: ts.Node, name: string, a: Attrs, api: string) => {
      if (!sensitiveCookie(name)) return;
      const problems: { what: string; severity: Severity }[] = [];
      if (a.httpOnly !== true && !a.dynamic.includes('httpOnly') && !a.dynamic.includes('options')) problems.push({ what: 'missing HttpOnly', severity: 'high' });
      if (a.secure !== true && !a.dynamic.includes('secure') && !a.dynamic.includes('options')) problems.push({ what: a.sameSite === 'none' ? 'SameSite=None without Secure' : 'missing Secure', severity: 'medium' });
      if (!problems.length) return;
      findings.push({
        node,
        message: `Session cookie '${name}' is issued (${api}) with ${problems.map((p) => p.what).join(' and ')}.`,
        confidence: 'high',
        severity: problems.some((p) => p.severity === 'high') ? 'high' : 'medium',
        evidenceKind: 'pattern',
        evidence: [`HttpOnly: ${a.httpOnly ?? 'not set'}`, `Secure: ${a.secure ?? 'not set'}`, `SameSite: ${a.sameSite ?? 'not set'}`, ...(a.dynamic.length ? [`not constant: ${a.dynamic.join(', ')}`] : [])],
      });
    };
    for (const call of ctx.index.calls) {
      const info = ctx.symbols.callee(call);
      const callee = strip(ctx, call.expression);
      const name = memberName(ctx, callee);
      const recv = receiverOf(ctx, callee);
      const a = call.arguments;
      if (!name || !a[0]) continue;
      if (name === 'cookie' && recv && a[1] && is(ctx.symbols.typeOrigin(recv), RESPONSE_MODULES, 'Response', 'ServerResponse')) {
        const n = ctx.symbols.constantString(a[0]);
        if (n) report(call, n, fromOptions(ctx, a[2]), 'res.cookie()');
      } else if (['setHeader', 'append', 'set', 'header'].includes(name) && a[1] && /^set-cookie$/i.test(ctx.symbols.constantString(a[0]) ?? '')) {
        const values = ctx.ts.isArrayLiteralExpression(strip(ctx, a[1])) ? [...(strip(ctx, a[1]) as ts.ArrayLiteralExpression).elements] : [a[1]];
        for (const v of values) {
          const text = urlParts(ctx, v).map((p) => p.text ?? '').join('');
          const m = /^\s*([^=;\s]+)\s*=/.exec(text);
          if (m) report(call, m[1]!, fromHeader(text), `Set-Cookie via ${name}()`);
        }
      } else if (name === 'serialize' && (is(info?.origin, 'cookie') || is(info?.receiver, 'cookie')) && a[1]) {
        const n = ctx.symbols.constantString(a[0]);
        if (n) report(call, n, fromOptions(ctx, a[2]), 'cookie.serialize()');
      }
    }
    return findings;
  },
});
