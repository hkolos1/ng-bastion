import type * as ts from 'typescript';
import { defineRule, type AnalysisContext, type Confidence, type RuleFinding } from '@ngbastion/plugin-api';
import { is, memberName, receiverOf, strip } from '../shared/common.js';
import { authCookieName } from '../shared/auth.js';
import { objectProp, urlParts } from '../shared/http.js';
import { classifyName, sensitiveValue } from '../shared/sensitivity.js';

interface CookieWrite {
  node: ts.Node;
  api: string;
  name?: string;
  value?: ts.Expression;
  /** Constant attribute text (`; Secure; SameSite=Strict`) or option names, lowercased. */
  attributes: string;
  attributesKnown: boolean;
}

function cookieWrites(ctx: AnalysisContext): CookieWrite[] {
  const t = ctx.ts;
  const out: CookieWrite[] = [];
  for (const a of ctx.index.assignments) {
    const left = strip(ctx, a.left);
    if (memberName(ctx, left) !== 'cookie' || !is(ctx.symbols.typeOrigin(receiverOf(ctx, left)!), 'dom', 'Document')) continue;
    if (a.operatorToken.kind !== t.SyntaxKind.EqualsToken) continue;
    const parts = urlParts(ctx, a.right);
    const text = parts.map((p) => p.text ?? '\uE000').join('');
    const m = /^\s*([^=;\s\uE000]+)\s*=/.exec(text);
    const valuePart = parts.find((p) => p.expr)?.expr;
    out.push({ node: a, api: 'document.cookie', ...(m ? { name: m[1]! } : {}), ...(valuePart ? { value: valuePart } : {}), attributes: text.slice(text.indexOf(';') >= 0 ? text.indexOf(';') : text.length).toLowerCase(), attributesKnown: true });
  }
  for (const call of ctx.index.calls) {
    const info = ctx.symbols.callee(call);
    if (!info || info.declaration || info.name !== 'set' || !call.arguments[1]) continue;
    const recv = receiverOf(ctx, strip(ctx, call.expression));
    const ngx = is(info.receiver, ['ngx-cookie-service', 'ngx-cookie-service-ssr'], 'CookieService', 'SsrCookieService');
    const jsCookie = is(info.receiver, 'js-cookie') || (!!recv && t.isIdentifier(strip(ctx, recv)) && (strip(ctx, recv) as ts.Identifier).text === 'Cookies' && is(ctx.symbols.typeOrigin(recv), 'js-cookie'));
    if (!ngx && !jsCookie) continue;
    const name = ctx.symbols.constantString(call.arguments[0]!);
    const opts = call.arguments[2];
    let attributes = '';
    let known = true;
    if (opts && t.isObjectLiteralExpression(strip(ctx, opts))) {
      const secure = objectProp(ctx, opts, 'secure');
      const sameSite = objectProp(ctx, opts, 'sameSite');
      if (secure && strip(ctx, secure).kind === t.SyntaxKind.TrueKeyword) attributes += '; secure';
      if (sameSite) attributes += `; samesite=${(ctx.symbols.constantString(sameSite) ?? '?').toLowerCase()}`;
    } else if (ngx && call.arguments.length >= 6) {
      // set(name, value, expires, path, domain, secure, sameSite)
      if (strip(ctx, call.arguments[5]!).kind === t.SyntaxKind.TrueKeyword) attributes += '; secure';
      if (call.arguments[6]) attributes += `; samesite=${(ctx.symbols.constantString(call.arguments[6]) ?? '?').toLowerCase()}`;
    } else if (opts) known = false;
    out.push({ node: call, api: ngx ? 'CookieService.set()' : 'Cookies.set() (js-cookie)', ...(name ? { name } : {}), value: call.arguments[1], attributes, attributesKnown: known });
  }
  return out;
}

export const ngb025 = defineRule({
  meta: {
    id: 'NGB025',
    name: 'Authentication cookie set from JavaScript',
    category: 'sensitive-data',
    defaultSeverity: 'high',
    cwe: ['CWE-1004', 'CWE-614'],
    docs: {
      description:
        "Reports session or authentication cookies written by browser code — `document.cookie = 'session=…'`, ngx-cookie-service `CookieService.set()`, js-cookie `Cookies.set()` — identified by the cookie name (`session`, `sid`, `auth_token`, `access_token`, `jwt`, …) or by a credential-named value. Missing `Secure` / `SameSite` attributes are added as evidence.",
      rationale:
        "Cookies created by JavaScript can never be `HttpOnly`, so any script running in the page (an XSS payload, a compromised third-party script) can read and exfiltrate the session. Session cookies should be issued by the server with `HttpOnly; Secure; SameSite`. Cookies without `Secure` are also sent over plain HTTP.",
      patterns: [
        "`document.cookie = 'token=' + value`, template literals, constant cookie strings (name from the constant prefix)",
        '`cookieService.set(name, value, …)` from `ngx-cookie-service` / `ngx-cookie-service-ssr`',
        '`Cookies.set(name, value, attrs)` from `js-cookie`',
        'Sensitive names: `session`, `sid`, `sessionId`, `auth`, `auth_token`, `access_token`, `refresh_token`, `id_token`, `jwt`, `token`, `remember_me` (and names classified as credentials); CSRF/XSRF cookies are ignored',
      ],
      limitations: [
        'Cookie names built dynamically are only reported when the value is identified as a credential.',
        'Cookies set through other wrappers or by the server (`Set-Cookie`, see NGB043) are not covered by this rule.',
      ],
      falsePositives: [
        'Non-secret cookies that happen to use a credential-like name (e.g. a `token` cookie holding a feature flag) can be reported.',
      ],
      remediation:
        "Issue session and token cookies from the server with `Set-Cookie: __Host-session=…; HttpOnly; Secure; SameSite=Lax; Path=/`. Keep access tokens in memory in the browser instead of cookies or storage.",
      example: {
        unsafe: "document.cookie = `access_token=${res.accessToken}; path=/`;",
        safe: '// Server: res.cookie("__Host-session", id, { httpOnly: true, secure: true, sameSite: "lax", path: "/" });',
      },
      references: [
        { title: 'OWASP — Session Management Cheat Sheet (cookies)', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#cookies' },
        { title: 'MDN — Set-Cookie: HttpOnly', url: 'https://developer.mozilla.org/docs/Web/HTTP/Headers/Set-Cookie#httponly' },
      ],
    },
  },
  analyze(ctx) {
    const findings: RuleFinding[] = [];
    for (const w of cookieWrites(ctx)) {
      const nameMatch = w.name ? (authCookieName(w.name) ? 'strong' : classifyName(w.name)?.category === 'credential' ? classifyName(w.name)!.strength : undefined) : undefined;
      const value = w.value ? sensitiveValue(ctx, w.value, { categories: ['credential'] }) : undefined;
      if (!nameMatch && !value) continue;
      let confidence: Confidence = nameMatch === 'strong' ? 'high' : nameMatch === 'weak' ? 'medium' : value!.confidence;
      if (nameMatch === 'weak' && value) confidence = 'high';
      const missing = w.attributesKnown ? ['secure', 'samesite'].filter((a) => !w.attributes.includes(a)) : [];
      findings.push({
        node: w.node,
        message: `Authentication cookie${w.name ? ` '${w.name}'` : ''} is set from JavaScript (${w.api}); it cannot be HttpOnly, so any script in the page can read it${missing.includes('secure') ? ', and it is not marked Secure' : ''}.`,
        confidence,
        evidenceKind: nameMatch ? 'pattern' : 'heuristic',
        evidence: [
          ...(w.name ? [`cookie name '${w.name}'${nameMatch ? ' identifies a session/credential cookie' : ''}`] : ['cookie name not constant']),
          ...(value?.evidence ?? []),
          ...(missing.length ? [`missing attributes: ${missing.join(', ')}`] : []),
        ],
        redactSnippet: true,
      });
    }
    return findings;
  },
});
