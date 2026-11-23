import type * as ts from 'typescript';
import { defineRule, type AnalysisContext, type Confidence, type RuleFinding } from '@ngbastion/plugin-api';
import { is, strip } from '../shared/common.js';
import { headerNames, objectLiteral, objectProp } from '../shared/http.js';
import { sensitiveValue } from '../shared/sensitivity.js';

/** Endpoints that typically return per-user or credential data. Shared with NGB032. */
export const USER_ENDPOINT = /\/(me|users?|account|accounts|profile|session|sessions|auth|oauth|token|tokens|identity|billing|wallet|payments?|orders?|cart|checkout|messages|inbox|notifications)(?=[/?#*'"]|$)/i;
const AUTH_HEADER = /^(authorization|x-api-key|x-auth-token|x-access-token|cookie)$/i;

interface RequestFacts {
  url?: string;
  authHeader: boolean;
}

/** What is known about a cache key: constant URL, or `new Request(url, { headers })`. */
function requestFacts(ctx: AnalysisContext, e: ts.Expression): RequestFacts {
  const t = ctx.ts;
  let x = strip(ctx, e);
  if (t.isIdentifier(x)) {
    const d = ctx.symbols.declarationOf(x);
    if (d && t.isVariableDeclaration(d) && d.initializer && t.isNewExpression(strip(ctx, d.initializer))) x = strip(ctx, d.initializer);
  }
  const constant = ctx.symbols.constantString(x);
  if (constant !== undefined) return { url: constant, authHeader: false };
  if (t.isNewExpression(x) && t.isIdentifier(x.expression) && x.expression.text === 'Request' && x.arguments?.[0]) {
    const url = ctx.symbols.constantString(x.arguments[0]);
    const init = objectLiteral(ctx, x.arguments[1]);
    const auth = headerNames(ctx, objectProp(ctx, init, 'headers')).some((h) => AUTH_HEADER.test(h));
    const cred = ctx.symbols.constantString(objectProp(ctx, init, 'credentials') ?? x) === 'include';
    return { ...(url !== undefined ? { url } : {}), authHeader: auth || cred };
  }
  // Template literal: use its constant head.
  if (t.isTemplateExpression(x)) return { url: x.head.text, authHeader: false };
  return { authHeader: false };
}

export const ngb031 = defineRule({
  meta: {
    id: 'NGB031',
    name: 'Sensitive data in CacheStorage',
    category: 'sensitive-data',
    defaultSeverity: 'medium',
    cwe: ['CWE-524', 'CWE-922'],
    docs: {
      description:
        "Reports application code that stores authenticated or user-specific responses in the browser's CacheStorage (`caches.open(…)` → `cache.put()` / `cache.add()` / `cache.addAll()`): requests carrying an `Authorization` header or credentials, user/account/session/payment endpoints, and response bodies that contain credentials or payment data.",
      rationale:
        "CacheStorage is persistent, origin-wide and survives logout and browser restarts unless the application deletes it. On shared or lost devices the next user (or any script running on the origin) can read cached account data, tokens or payment details with `caches.match()`. Unlike HTTP caching it ignores `Cache-Control: no-store`.",
      patterns: [
        '`cache.put(request, response)`, `cache.add(request)`, `cache.addAll([...])` on a DOM `Cache` (from `caches.open()`, typed or inferred)',
        "Request evidence: `new Request(url, { headers: { Authorization } })` or `credentials: 'include'` (high); constant URLs such as `/api/me`, `/account`, `/session`, `/orders`, `/payments` (medium)",
        'Response evidence: credential or payment names in the cached response / body (`new Response(JSON.stringify({ accessToken }))`)',
      ],
      limitations: [
        'Cache keys built dynamically without a constant prefix are not classified.',
        'Code inside service workers is covered by NGB032, which also analyzes Angular `ngsw-config.json`.',
        'Whether the application clears the cache on logout (`caches.delete()`) is not verified.',
      ],
      falsePositives: [
        'Endpoints matched by name (e.g. a public `/api/orders/statuses` list) can be reported; suppress with a justification.',
      ],
      remediation:
        "Do not put authenticated responses into CacheStorage. If offline access is required, cache only non-personal data, scope cache names per user, and delete them on logout (`caches.delete(name)`).",
      example: {
        unsafe: `const cache = await caches.open('api');
await cache.put('/api/account', await fetch('/api/account', { credentials: 'include' }));`,
        safe: `const cache = await caches.open('static-v1');
await cache.addAll(['/assets/i18n/en.json', '/assets/logo.svg']);`,
      },
      references: [
        { title: 'MDN — Cache API', url: 'https://developer.mozilla.org/docs/Web/API/Cache' },
        { title: 'OWASP — Session Management: logout and client-side data', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html' },
      ],
    },
  },
  analyze(ctx) {
    const findings: RuleFinding[] = [];
    const t = ctx.ts;
    for (const call of ctx.index.calls) {
      const info = ctx.symbols.callee(call);
      if (!info || info.declaration || !['put', 'add', 'addAll'].includes(info.name) || !is(info.receiver, 'dom', 'Cache')) continue;
      const keys = info.name === 'addAll' && call.arguments[0] && t.isArrayLiteralExpression(strip(ctx, call.arguments[0]))
        ? [...(strip(ctx, call.arguments[0]) as ts.ArrayLiteralExpression).elements]
        : call.arguments[0] ? [call.arguments[0]] : [];
      let confidence: Confidence | undefined;
      const evidence: string[] = [];
      for (const k of keys) {
        const f = requestFacts(ctx, k);
        if (f.authHeader) {
          confidence = 'high';
          evidence.push('cached request carries an Authorization header or credentials');
        } else if (f.url && USER_ENDPOINT.test(f.url)) {
          confidence ??= 'medium';
          evidence.push(`user-specific endpoint '${f.url}'`);
        }
      }
      let body = info.name === 'put' ? call.arguments[1] : undefined;
      // new Response(JSON.stringify({ accessToken })) → classify the body text.
      if (body && t.isNewExpression(strip(ctx, body)) && (strip(ctx, body) as ts.NewExpression).arguments?.[0]) body = (strip(ctx, body) as ts.NewExpression).arguments![0];
      const s = body ? sensitiveValue(ctx, body) : undefined;
      if (s) {
        confidence = confidence === 'high' || s.confidence === 'high' ? 'high' : 'medium';
        evidence.push(...s.evidence);
      }
      if (!confidence) continue;
      findings.push({
        node: call,
        message: `cache.${info.name}() stores authenticated or user-specific data in CacheStorage, where it persists after logout and is readable by any script on the origin.`,
        confidence,
        evidenceKind: 'heuristic',
        evidence,
      });
    }
    return findings;
  },
});
