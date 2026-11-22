import type * as ts from 'typescript';
import { defineRule, type AnalysisContext, type RuleFinding, type Severity } from '@ngbastion/plugin-api';
import { memberName, receiverOf, strip } from '../shared/common.js';
import { classifyName } from '../shared/sensitivity.js';
import { urlValidation } from '../shared/url-guards.js';

const SENSITIVE_HEADERS = new Set(['authorization', 'proxy-authorization', 'cookie', 'x-api-key', 'x-auth-token', 'x-access-token', 'api-key', 'apikey']);

function isSensitiveHeader(name: string): boolean {
  const n = name.toLowerCase();
  if (SENSITIVE_HEADERS.has(n)) return true;
  if (/^x-(xsrf|csrf)-token$/.test(n)) return false;
  return classifyName(name)?.category === 'credential';
}

/** Interceptor functions: `HttpInterceptorFn` values, functions in `withInterceptors([...])`, `HttpInterceptor.intercept()`. */
function interceptors(ctx: AnalysisContext): ts.SignatureDeclaration[] {
  const t = ctx.ts;
  const out = new Set<ts.SignatureDeclaration>();
  const typeName = (n: ts.TypeNode | undefined) => (n && t.isTypeReferenceNode(n) ? n.typeName.getText() : undefined);
  for (const sf of ctx.sourceFiles) {
    const visit = (n: ts.Node): void => {
      if (t.isVariableDeclaration(n) && typeName(n.type) === 'HttpInterceptorFn' && n.initializer) {
        const fn = ctx.flow.resolveFunction(n.initializer);
        if (fn) out.add(fn);
      }
      if (t.isClassDeclaration(n) && n.heritageClauses?.some((h) => h.types.some((x) => x.expression.getText() === 'HttpInterceptor'))) {
        for (const m of n.members) if (t.isMethodDeclaration(m) && m.name.getText() === 'intercept') out.add(m);
      }
      t.forEachChild(n, visit);
    };
    visit(sf);
  }
  for (const call of ctx.index.calls) {
    const callee = strip(ctx, call.expression);
    if (!t.isIdentifier(callee) || callee.text !== 'withInterceptors' || !call.arguments[0]) continue;
    const arr = strip(ctx, call.arguments[0]);
    if (!t.isArrayLiteralExpression(arr)) continue;
    for (const el of arr.elements) {
      const fn = ctx.flow.resolveFunction(el);
      if (fn) out.add(fn);
    }
  }
  return [...out];
}

interface Forwarded {
  what: string;
  severity: Severity;
}

/** What credential material a `req.clone({...})` call attaches. */
function forwarded(ctx: AnalysisContext, clone: ts.CallExpression): Forwarded[] {
  const t = ctx.ts;
  const arg = clone.arguments[0] && strip(ctx, clone.arguments[0]);
  if (!arg || !t.isObjectLiteralExpression(arg)) return [];
  const out: Forwarded[] = [];
  const keyOf = (p: ts.ObjectLiteralElementLike) => (p.name && (t.isIdentifier(p.name) || t.isStringLiteralLike(p.name)) ? p.name.text : undefined);
  for (const p of arg.properties) {
    const key = keyOf(p);
    const init = t.isPropertyAssignment(p) ? strip(ctx, p.initializer) : undefined;
    if (key === 'withCredentials' && init?.kind === t.SyntaxKind.TrueKeyword) out.push({ what: 'withCredentials: true (cookies)', severity: 'medium' });
    if (key === 'setHeaders' && init && t.isObjectLiteralExpression(init)) {
      for (const h of init.properties) {
        const name = keyOf(h);
        if (name && isSensitiveHeader(name)) out.push({ what: `${name} header`, severity: 'high' });
      }
    }
    if (key === 'headers' && init) {
      const walk = (n: ts.Node): void => {
        if (t.isCallExpression(n) && ['set', 'append'].includes(memberName(ctx, n.expression) ?? '') && n.arguments[0]) {
          const name = ctx.symbols.constantString(n.arguments[0]);
          if (name && isSensitiveHeader(name)) out.push({ what: `${name} header`, severity: 'high' });
        }
        t.forEachChild(n, walk);
      };
      walk(init);
    }
  }
  return out;
}

export const ngb013 = defineRule({
  meta: {
    id: 'NGB013',
    name: 'Credential forwarding risk',
    category: 'navigation-auth',
    defaultSeverity: 'high',
    cwe: ['CWE-522', 'CWE-200'],
    docs: {
      description:
        'Analyzes Angular HTTP interceptors (functional `HttpInterceptorFn`, functions registered with `withInterceptors()`, and classes implementing `HttpInterceptor`) and reports `req.clone()` calls that attach `Authorization`/API-key/token headers or `withCredentials: true` without first checking that the request goes to a trusted destination.',
      rationale:
        'Interceptors run for every `HttpClient` request, including calls to third-party APIs, CDNs and user-supplied URLs. An unconditional `Authorization` header leaks the user\'s bearer token to every one of those hosts.',
      patterns: [
        '`req.clone({ setHeaders: { Authorization: … } })`, `req.clone({ headers: req.headers.set("Authorization", …) })`, sensitive headers such as `X-Api-Key`, `X-Auth-Token`, `Cookie`, or names classified as credentials',
        '`req.clone({ withCredentials: true })` (reported with medium severity)',
        'Recognized destination checks (if / early return / ternary, including `const isApi = …` variables): `req.url.startsWith(environment.apiUrl)` or a constant `https://host/`, relative URLs (`startsWith("/")` and not `//`), `new URL(req.url).origin === …`, allowlists (`ALLOWED.some(u => req.url.startsWith(u))`, `.includes(new URL(req.url).origin)`)',
        'Weak checks (`req.url.includes("api")`, `startsWith("http")`, unanchored regexes) lower the confidence to medium; unknown project validators lower it to low',
      ],
      limitations: [
        'Checks performed outside the interceptor (e.g. a separate HttpClient instance via `HttpBackend`) are not seen; such interceptors may still be reported.',
        'Header names built dynamically are not evaluated.',
        'CSRF/XSRF token headers are intentionally not reported.',
      ],
      falsePositives: [
        'Applications that only ever call a single backend may still be reported; adding an explicit destination check documents that assumption and protects future third-party calls.',
      ],
      remediation:
        'Attach credentials only when the request URL targets your API origin: `if (!req.url.startsWith(environment.apiUrl)) return next(req);` before cloning, or compare `new URL(req.url, location.origin).origin` against an allowlist.',
      example: {
        unsafe: `export const authInterceptor: HttpInterceptorFn = (req, next) =>
  next(req.clone({ setHeaders: { Authorization: \`Bearer \${inject(Auth).token()}\` } }));`,
        safe: `export const authInterceptor: HttpInterceptorFn = (req, next) => {
  if (!req.url.startsWith(environment.apiUrl)) return next(req);
  return next(req.clone({ setHeaders: { Authorization: \`Bearer \${inject(Auth).token()}\` } }));
};`,
      },
      references: [{ title: 'Angular — Interceptors', url: 'https://angular.dev/guide/http/interceptors' }],
    },
  },
  analyze(ctx) {
    const t = ctx.ts;
    const findings: RuleFinding[] = [];
    for (const fn of interceptors(ctx)) {
      const req = fn.parameters[0];
      if (!req || !t.isIdentifier(req.name)) continue;
      const reqName = req.name.text;
      const body = (fn as { body?: ts.Node }).body;
      if (!body) continue;
      const clones: ts.CallExpression[] = [];
      const walk = (n: ts.Node): void => {
        if (t.isCallExpression(n) && memberName(ctx, n.expression) === 'clone') {
          const recv = receiverOf(ctx, n.expression);
          if (recv && t.isIdentifier(strip(ctx, recv)) && (strip(ctx, recv) as ts.Identifier).text === reqName) clones.push(n);
        }
        t.forEachChild(n, walk);
      };
      walk(body);
      for (const clone of clones) {
        const what = forwarded(ctx, clone);
        if (!what.length) continue;
        const v = urlValidation(ctx, clone, new Set([reqName]));
        if (v.host === 'strong') continue;
        const severity: Severity = what.some((w) => w.severity === 'high') ? 'high' : 'medium';
        const items = what.map((w) => w.what).join(', ');
        findings.push({
          node: clone,
          message: v.host === 'weak'
            ? `Interceptor attaches ${items} using a bypassable destination check; credentials can reach unintended hosts.`
            : v.host === 'custom'
              ? `Interceptor attaches ${items} after a custom destination check that NgBastion cannot verify.`
              : `Interceptor attaches ${items} to every request regardless of destination; credentials can be forwarded to third-party or attacker-chosen hosts.`,
          confidence: v.host === 'weak' ? 'medium' : v.host === 'custom' ? 'low' : 'high',
          severity,
          evidenceKind: 'pattern',
          evidence: [`attached: ${items}`, ...(v.evidence.length ? v.evidence.map((e) => `guard: ${e}`) : ['no destination check on the request URL'])],
        });
      }
    }
    return findings;
  },
});
