import type * as ts from 'typescript';
import { defineRule, type AnalysisContext, type Confidence, type RuleFinding } from '@ngbastion/plugin-api';
import { memberName, receiverOf, strip } from '../shared/common.js';
import { sensitiveValue, words } from '../shared/sensitivity.js';
import { isServerFile } from '../shared/server.js';

const MUTATORS = new Set(['set', 'push', 'unshift', 'add', 'splice', 'assign']);
const PER_USER = new Set(['user', 'users', 'session', 'sessions', 'profile', 'account', 'customer', 'tenant', 'auth', 'cart', 'basket', 'order', 'orders', 'me', 'identity', 'principal', 'claims', 'permissions', 'roles']);
const UNTRUSTED_KINDS = new Set(['url', 'http-response', 'cookie', 'request-header', 'user-input', 'storage', 'message']);

/** Whether the project renders on the server (Angular SSR / Universal entry points or angular.json SSR options). */
function hasSsr(ctx: AnalysisContext): boolean {
  if (ctx.sourceFiles.some((sf) => /(^|[/\\])(server|main\.server|app\.config\.server)\.ts$/.test(sf.fileName))) return true;
  const build = ((ctx.project.angularProject?.['architect'] as Record<string, Record<string, unknown>> | undefined)?.['build']?.['options'] ?? {}) as Record<string, unknown>;
  return !!build['ssr'] || !!build['server'];
}

/** Top-level `let x` and `const x = new Map() | [] | {}` declarations (mutable module state). */
function moduleState(ctx: AnalysisContext, sf: ts.SourceFile): Map<ts.Declaration, string> {
  const t = ctx.ts;
  const out = new Map<ts.Declaration, string>();
  for (const st of sf.statements) {
    if (!t.isVariableStatement(st)) continue;
    const isConst = !!(st.declarationList.flags & t.NodeFlags.Const);
    for (const d of st.declarationList.declarations) {
      if (!t.isIdentifier(d.name)) continue;
      if (!isConst) {
        out.set(d, d.name.text);
        continue;
      }
      const init = d.initializer && strip(ctx, d.initializer);
      if (!init) continue;
      const mutable = t.isArrayLiteralExpression(init) || t.isObjectLiteralExpression(init)
        || (t.isNewExpression(init) && t.isIdentifier(init.expression) && ['Map', 'Set', 'Array', 'Object'].includes(init.expression.text));
      if (mutable) out.set(d, d.name.text);
    }
  }
  return out;
}

/** `isPlatformBrowser(...)` / `typeof window !== 'undefined'` guards keep the write off the server. */
function browserOnly(ctx: AnalysisContext, node: ts.Node): boolean {
  return ctx.flow.guards(node).some((g) => {
    const text = g.condition.getText();
    if (/\bisPlatformBrowser\s*\(/.test(text)) return g.whenTrue;
    if (/\bisPlatformServer\s*\(/.test(text)) return !g.whenTrue;
    if (/typeof\s+(window|document)\s*!==?\s*['"]undefined['"]/.test(text)) return g.whenTrue;
    return false;
  });
}

function rootIdentifier(ctx: AnalysisContext, e: ts.Expression): ts.Identifier | undefined {
  const t = ctx.ts;
  let x = strip(ctx, e);
  while (t.isPropertyAccessExpression(x) || t.isElementAccessExpression(x)) x = strip(ctx, x.expression);
  return t.isIdentifier(x) ? x : undefined;
}

export const ngb055 = defineRule({
  meta: {
    id: 'NGB055',
    name: 'Cross-request state in SSR module scope',
    category: 'ssr',
    defaultSeverity: 'medium',
    cwe: ['CWE-488', 'CWE-200', 'CWE-362'],
    docs: {
      description:
        "In projects that render on the server, reports writes of user- or request-specific data into module-level mutable state (`let currentUser`, `const cache = new Map()` at the top of a file) from functions and class members of the Angular application. Evidence for \"user-specific\": credentials / payment data (high), values traced from HTTP responses, the URL, cookies or request headers (medium), or per-user names such as `user`, `session`, `tenant`, `cart` (low). Writes guarded by `isPlatformBrowser()` or `typeof window !== 'undefined'` are ignored.",
      rationale:
        "In the browser every user has their own copy of a module. On the server, one Node.js process renders requests from many users concurrently and modules are evaluated once: a top-level `let currentUser` set while rendering Alice's request is still there — or already overwritten — while Bob's page renders. Angular's root injector is created per request, so the same data in an injectable service would be isolated; module-level variables are not.",
      patterns: [
        'Project with SSR: `server.ts` / `main.server.ts` / `app.config.server.ts`, or `ssr` / `server` options in angular.json',
        'Top-level `let x` and `const x = new Map() | new Set() | [] | {}` in application files (server entry files and Node-only files are excluded)',
        'Writes from inside functions: `x = v`, `x.prop = v`, `x[k] = v`, `x.set(k, v)`, `x.push(v)`, `x.add(v)`, `Object.assign(x, v)`',
      ],
      limitations: [
        'Module state shared through imported objects (`import { store } from …; store.user = u`) is followed only when the declaration is in the same project.',
        'Third-party libraries with process-wide singletons are not inspected.',
        'Whether the server process actually serves concurrent users (e.g. prerendering only) is not known; such projects can turn the rule off.',
      ],
      falsePositives: [
        'Caches of data that is identical for every user (feature flags, translations) are only reported when named or traced like user data; name-only evidence is low confidence.',
      ],
      remediation:
        "Keep request- and user-specific state in injectable services (root services are per request on the server), signals inside components, or `TransferState`. For genuinely global caches, key them by something that cannot leak (never by the user) and store only public data.",
      example: {
        unsafe: `let currentUser: User | undefined;
@Injectable({ providedIn: 'root' }) export class Auth {
  load() { return this.http.get<User>('/api/me').pipe(tap((u) => (currentUser = u))); }
}`,
        safe: `@Injectable({ providedIn: 'root' }) export class Auth {
  readonly user = signal<User | undefined>(undefined);
  load() { return this.http.get<User>('/api/me').pipe(tap((u) => this.user.set(u))); }
}`,
      },
      references: [
        { title: 'Angular — Server-side rendering: authoring server-compatible components', url: 'https://angular.dev/guide/ssr' },
        { title: 'Node.js — Don’t block the event loop (shared process state)', url: 'https://nodejs.org/en/learn/asynchronous-work/dont-block-the-event-loop' },
      ],
    },
  },
  analyze(ctx) {
    const t = ctx.ts;
    if (!hasSsr(ctx)) return [];
    const findings: RuleFinding[] = [];
    const state = new Map<ts.Declaration, string>();
    for (const sf of ctx.sourceFiles) {
      if (sf.fileName.endsWith('.json') || isServerFile(ctx, sf)) continue;
      for (const [d, n] of moduleState(ctx, sf)) state.set(d, n);
    }
    if (!state.size) return findings;
    const reported = new Set<ts.Declaration>();

    const evidence = (value: ts.Expression, target: string): { confidence: Confidence; severity: 'high' | 'medium'; why: string } | undefined => {
      const s = sensitiveValue(ctx, value);
      if (s) return { confidence: s.confidence === 'high' ? 'high' : 'medium', severity: 'high', why: s.evidence[0]! };
      const flow = ctx.taint.trace(value, { context: 'generic' }).flows.find((f) => UNTRUSTED_KINDS.has(f.source.kind));
      if (flow) return { confidence: 'medium', severity: 'medium', why: `value comes from ${flow.source.description}` };
      const names = [target, ...(t.isIdentifier(strip(ctx, value)) ? [(strip(ctx, value) as ts.Identifier).text] : [])];
      const named = names.find((n) => words(n).some((w) => PER_USER.has(w)));
      if (named) return { confidence: 'low', severity: 'medium', why: `per-user name '${named}'` };
      return undefined;
    };

    const check = (node: ts.Node, target: ts.Expression, value: ts.Expression | undefined, how: string) => {
      const id = rootIdentifier(ctx, target);
      const d = id && ctx.symbols.declarationOf(id);
      if (!d || !state.has(d) || reported.has(d) || !value) return;
      // Only writes from functions run per request; top-level initialization runs once.
      if (!ctx.flow.enclosingFunction(node) || browserOnly(ctx, node)) return;
      const ev = evidence(value, memberName(ctx, target) ?? state.get(d)!);
      if (!ev) return;
      reported.add(d);
      findings.push({
        node,
        message: `Module-level '${state.get(d)}' is shared by all requests rendered by the SSR server; ${how} stores user-specific data in it (${ev.why}), which can leak into other users' pages.`,
        confidence: ev.confidence,
        severity: ev.severity,
        evidenceKind: ev.confidence === 'low' ? 'heuristic' : 'pattern',
        evidence: [`declared at ${ctx.location(d).line}:${ctx.location(d).column} in module scope`, ev.why, 'project renders on the server'],
      });
    };

    for (const a of ctx.index.assignments) check(a, a.left, a.right, 'this assignment');
    for (const call of ctx.index.calls) {
      const m = memberName(ctx, call.expression);
      if (!m || !MUTATORS.has(m)) continue;
      const recv = receiverOf(ctx, call.expression);
      if (m === 'assign' && recv && strip(ctx, recv).getText() === 'Object' && call.arguments[0]) check(call, call.arguments[0], call.arguments[1], 'Object.assign()');
      else if (recv && m !== 'assign') check(call, recv, call.arguments[call.arguments.length - 1], `${m}()`);
    }
    return findings;
  },
});
