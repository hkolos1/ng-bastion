import type * as ts from 'typescript';
import { defineRule, lowerConfidence, type AnalysisContext, type Confidence, type RuleFinding } from '@ngbastion/plugin-api';
import { is, receiverOf, strip } from '../shared/common.js';
import { describeEvidence, sensitivityOf, words } from '../shared/sensitivity.js';

/** Per-user data that should not be serialized into shared, cacheable HTML. */
const PERSONAL = new Set(['user', 'users', 'profile', 'session', 'account', 'me', 'customer', 'email', 'address', 'phone', 'identity', 'principal', 'claims', 'permissions', 'roles', 'wallet', 'billing']);
const AUTH_URL = /\/(me|users?|account|profile|session|auth|identity|billing|wallet)(?=[/?#'"]|$)/i;
const SENSITIVE_HEADERS = new Set(['authorization', 'set-cookie', 'cookie', 'proxy-authorization', 'x-api-key', 'x-auth-token']);

function personalName(name: string): boolean {
  return words(name).some((w) => PERSONAL.has(w));
}

function stateKeyName(ctx: AnalysisContext, key: ts.Expression): string | undefined {
  const t = ctx.ts;
  let e = strip(ctx, key);
  if (t.isIdentifier(e) || t.isPropertyAccessExpression(e)) {
    const d = ctx.symbols.declarationOf(e);
    if (d && (t.isVariableDeclaration(d) || t.isPropertyDeclaration(d)) && d.initializer) e = strip(ctx, d.initializer);
  }
  if (t.isCallExpression(e) && /makeStateKey$/.test(e.expression.getText()) && e.arguments[0]) return ctx.symbols.constantString(e.arguments[0]);
  return ctx.symbols.constantString(e);
}

function objectProp(ctx: AnalysisContext, obj: ts.ObjectLiteralExpression, name: string): ts.Expression | undefined {
  const t = ctx.ts;
  for (const p of obj.properties) {
    if (t.isPropertyAssignment(p) && p.name.getText().replace(/['"]/g, '') === name) return p.initializer;
  }
  return undefined;
}

export const ngb020 = defineRule({
  meta: {
    id: 'NGB020',
    name: 'Sensitive SSR transfer cache',
    category: 'ssr',
    defaultSeverity: 'high',
    cwe: ['CWE-524', 'CWE-200'],
    docs: {
      description:
        'Reports Angular SSR state transfer that may serialize per-user or credential data into the rendered HTML: `TransferState.set()` with values or keys that carry credentials or personal data (user, profile, session, account, …) or that come from authenticated-looking HTTP endpoints, and `withHttpTransferCacheOptions()` configured to cache requests with auth headers or to include sensitive response headers.',
      rationale:
        'Transferred state is embedded as JSON in the server-rendered HTML. If that HTML is cached by a CDN or shared cache, or rendered for one user and served to another, the embedded per-user data and tokens leak to other visitors. By default Angular\'s HTTP transfer cache skips requests with `Authorization` headers for this reason.',
      patterns: [
        '`transferState.set(key, value)` where `transferState` is `TransferState` from `@angular/core`',
        'Evidence: credential/payment names on the value (NGB014/NGB016 vocabulary, high confidence); personal-data names on the value or its type, or a traced `HttpClient` response from `/me`, `/user`, `/account`, `/profile`, `/session`, `/auth` URLs (medium); a personal state-key name only (low)',
        '`withHttpTransferCacheOptions({ includeRequestsWithAuthHeaders: true })` and `includeHeaders` containing `authorization`, `cookie`, `set-cookie`, `x-api-key` (lower confidence when a `filter` function is present)',
      ],
      limitations: [
        'Whether the SSR response is actually cached or shared between users depends on deployment (CDN rules, `Cache-Control`) and cannot be determined statically.',
        'Cookie-authenticated requests cached by the HTTP transfer cache are not detected: whether a request carries cookies is decided at runtime.',
        'The body of a custom `filter` function is not evaluated.',
      ],
      falsePositives: [
        'Pages rendered per request with `Cache-Control: private, no-store` limit exposure to the requesting user; such findings can be documented as exceptions.',
        'Public data with personal-sounding names (e.g. a public author `profile`) may be reported with medium confidence.',
      ],
      remediation:
        'Do not transfer credentials. Transfer only public, shareable state; fetch per-user data on the client after hydration, or ensure SSR responses containing user data are never cached (`Cache-Control: private, no-store`). Keep the default HTTP transfer cache behaviour of skipping authenticated requests.',
      example: {
        unsafe: `this.http.get<User>('/api/me').subscribe(u => this.state.set(USER_KEY, u));`,
        safe: `this.http.get<Product[]>('/api/products').subscribe(p => this.state.set(PRODUCTS_KEY, p));`,
      },
      references: [{ title: 'Angular — HTTP transfer cache (SSR)', url: 'https://angular.dev/guide/ssr#caching-data-when-using-httpclient' }],
    },
  },
  analyze(ctx) {
    const t = ctx.ts;
    const findings: RuleFinding[] = [];
    for (const call of ctx.index.calls) {
      const callee = strip(ctx, call.expression);
      const info = ctx.symbols.callee(call);
      if (!info || info.declaration) continue;

      if (info.name === 'set' && call.arguments.length >= 2) {
        const recv = receiverOf(ctx, callee);
        if (!recv || !is(ctx.symbols.typeOrigin(recv), ['@angular/core', '@angular/platform-browser'], 'TransferState')) continue;
        const [key, value] = [call.arguments[0]!, call.arguments[1]!];
        const trace = ctx.taint.trace(value, { context: 'generic' });
        const evidence: string[] = [];
        let confidence: Confidence | undefined;
        const sens = sensitivityOf(ctx, value, trace).filter((e) => e.match.strength === 'strong');
        if (sens.length) {
          confidence = 'high';
          evidence.push(...sens.slice(0, 3).map(describeEvidence));
        }
        const personal = [...new Set([value.getText(), ...trace.names, ...ctx.symbols.propertyNames(value)])].filter((n) => /^[\w$.]+$/.test(n) && personalName(n));
        const authFlow = trace.flows.find((f) => f.source.kind === 'http-response' && AUTH_URL.test(f.source.description));
        if (authFlow) evidence.push(`value comes from ${authFlow.source.description}`);
        if (personal.length) evidence.push(`personal-data names: ${personal.slice(0, 4).join(', ')}`);
        if (!confidence && (authFlow || personal.length)) confidence = 'medium';
        const keyName = stateKeyName(ctx, key);
        if (keyName && personalName(keyName)) {
          evidence.push(`state key '${keyName}'`);
          confidence ??= 'low';
        }
        if (!confidence) continue;
        findings.push({
          node: call,
          message: `TransferState.set() serializes ${sens.length ? 'credential data' : 'per-user data'} into the server-rendered HTML; cached or shared SSR responses would expose it to other users.`,
          confidence,
          evidenceKind: sens.length ? 'pattern' : 'heuristic',
          ...(authFlow ? { trace: [...authFlow.steps, { kind: 'sink' as const, location: ctx.location(call), description: 'serialized into SSR transfer state' }] } : {}),
          evidence,
        });
        continue;
      }

      if (info.name === 'withHttpTransferCacheOptions' && call.arguments[0]) {
        const opts = strip(ctx, call.arguments[0]);
        if (!t.isObjectLiteralExpression(opts)) continue;
        const hasFilter = !!objectProp(ctx, opts, 'filter');
        const report = (node: ts.Node, message: string) => findings.push({
          node,
          message,
          confidence: hasFilter ? lowerConfidence('high') : 'high',
          evidenceKind: 'pattern',
          evidence: hasFilter ? ['a custom filter() is configured; its logic was not evaluated'] : [],
        });
        const withAuth = objectProp(ctx, opts, 'includeRequestsWithAuthHeaders');
        if (withAuth && withAuth.kind === t.SyntaxKind.TrueKeyword) {
          report(withAuth, 'HTTP transfer cache includes requests with Authorization headers; authenticated responses are serialized into the SSR HTML.');
        }
        const headers = objectProp(ctx, opts, 'includeHeaders');
        if (headers && t.isArrayLiteralExpression(strip(ctx, headers))) {
          const names = (strip(ctx, headers) as ts.ArrayLiteralExpression).elements
            .map((e) => ctx.symbols.constantString(e)?.toLowerCase())
            .filter((h): h is string => !!h && SENSITIVE_HEADERS.has(h));
          if (names.length) report(headers, `HTTP transfer cache serializes sensitive response headers (${names.join(', ')}) into the SSR HTML.`);
        }
      }
    }
    return findings;
  },
});
