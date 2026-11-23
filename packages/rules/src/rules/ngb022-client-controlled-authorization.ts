import type * as ts from 'typescript';
import { defineRule, lowerConfidence, type AnalysisContext, type RuleFinding, type TaintFlow } from '@ngbastion/plugin-api';
import { flowEvidence, sinkStep, strip } from '../shared/common.js';
import { words } from '../shared/sensitivity.js';

const GUARD_TYPES = new Set(['CanActivateFn', 'CanActivateChildFn', 'CanMatchFn', 'CanLoadFn']);
const GUARD_INTERFACES = new Set(['CanActivate', 'CanActivateChild', 'CanMatch', 'CanLoad']);
const GUARD_METHODS = new Set(['canActivate', 'canActivateChild', 'canMatch', 'canLoad']);
const AUTHZ_WORDS = new Set(['role', 'roles', 'admin', 'administrator', 'permission', 'permissions', 'privilege', 'privileges', 'entitlement', 'entitlements', 'superuser', 'staff', 'moderator', 'authorized', 'authorised', 'isadmin', 'grants', 'acl']);
const CONTROLLABLE = new Set(['url', 'storage', 'cookie', 'window-name', 'referrer']);

/** Route guard functions: typed `CanActivateFn` etc., functions in `canActivate: [...]` route arrays, and guard classes. */
function guardFunctions(ctx: AnalysisContext): ts.SignatureDeclaration[] {
  const t = ctx.ts;
  const out = new Set<ts.SignatureDeclaration>();
  const addClass = (cls: ts.ClassDeclaration) => {
    for (const m of cls.members) if (t.isMethodDeclaration(m) && GUARD_METHODS.has(m.name.getText())) out.add(m);
  };
  for (const sf of ctx.sourceFiles) {
    const visit = (n: ts.Node): void => {
      if (t.isVariableDeclaration(n) && n.type && t.isTypeReferenceNode(n.type) && GUARD_TYPES.has(n.type.typeName.getText()) && n.initializer) {
        const fn = ctx.flow.resolveFunction(n.initializer);
        if (fn) out.add(fn);
      }
      if (t.isClassDeclaration(n) && n.heritageClauses?.some((h) => h.types.some((x) => GUARD_INTERFACES.has(x.expression.getText())))) addClass(n);
      if (t.isPropertyAssignment(n) && GUARD_METHODS.has(n.name.getText()) && t.isArrayLiteralExpression(strip(ctx, n.initializer))) {
        for (const el of (strip(ctx, n.initializer) as ts.ArrayLiteralExpression).elements) {
          const d = ctx.symbols.declarationOf(el);
          if (d && t.isClassDeclaration(d)) addClass(d);
          else {
            const fn = ctx.flow.resolveFunction(el);
            if (fn) out.add(fn);
          }
        }
      }
      t.forEachChild(n, visit);
    };
    visit(sf);
  }
  return [...out];
}

/** Expressions that decide the guard outcome: returned values and branch conditions. */
function decisions(ctx: AnalysisContext, fn: ts.SignatureDeclaration): ts.Expression[] {
  const t = ctx.ts;
  const out: ts.Expression[] = [];
  const body = (fn as { body?: ts.Node }).body;
  if (!body) return out;
  if (!t.isBlock(body)) return [body as ts.Expression];
  const visit = (n: ts.Node): void => {
    if (n !== body && t.isFunctionLike(n) && !t.isArrowFunction(n)) return;
    if (t.isReturnStatement(n) && n.expression) out.push(n.expression);
    if (t.isIfStatement(n)) out.push(n.expression);
    if (t.isConditionalExpression(n)) out.push(n.condition);
    t.forEachChild(n, visit);
  };
  visit(body);
  return out;
}

/** Maximal value expressions inside a decision (operands of comparisons, negations, logical operators). */
function operands(ctx: AnalysisContext, e: ts.Expression, out: ts.Expression[] = []): ts.Expression[] {
  const t = ctx.ts;
  const x = strip(ctx, e);
  if (t.isBinaryExpression(x)) {
    operands(ctx, x.left, out);
    operands(ctx, x.right, out);
  } else if (t.isPrefixUnaryExpression(x)) operands(ctx, x.operand, out);
  else if (t.isConditionalExpression(x)) [x.condition, x.whenTrue, x.whenFalse].forEach((y) => operands(ctx, y, out));
  else if (t.isCallExpression(x) || t.isPropertyAccessExpression(x) || t.isElementAccessExpression(x) || t.isIdentifier(x)) out.push(x);
  return out;
}

const authzName = (names: string[]) => names.find((n) => words(n).some((w) => AUTHZ_WORDS.has(w)) || AUTHZ_WORDS.has(n.toLowerCase()));

export const ngb022 = defineRule({
  meta: {
    id: 'NGB022',
    name: 'Authorization decision from user-controllable state',
    category: 'navigation-auth',
    defaultSeverity: 'medium',
    cwe: ['CWE-602', 'CWE-807'],
    docs: {
      description:
        'Reports Angular route guards (`CanActivateFn`, `CanMatchFn`, `CanActivateChildFn`, `CanLoadFn`, and guard classes) whose decision is traced to a role, permission or admin flag read from state the user controls: URL parameters, Web Storage, cookies or `window.name`. Decisions based on server responses or in-memory state are not reported.',
      rationale:
        'Route guards only decide what the browser navigates to. A role read from `localStorage` or a query parameter can be changed by the user in seconds, so the guard is a UI convenience, not access control. This is harmless if every API behind the guarded area enforces authorization on the server, and a privilege-escalation bug if it does not. The finding marks the places where that assumption must be verified.',
      patterns: [
        'Guards declared as `const g: CanActivateFn = …`, functions and guard classes listed in `canActivate` / `canMatch` / `canActivateChild` / `canLoad` route arrays, classes implementing `CanActivate` etc.',
        'Decision expressions: returned values, `if` conditions and ternaries inside the guard; values are traced through services and helpers (taint engine)',
        'Sources: ActivatedRoute / `location` URL values, `localStorage` / `sessionStorage` reads, `document.cookie`, `window.name`',
        'Only values named like authorization data are reported: `role`, `roles`, `isAdmin`, `permissions`, `privileges`, `entitlements`, `superuser`, …',
      ],
      limitations: [
        'Server-side authorization is not visible. A finding does not mean the protected data is exposed; it means the client-side check alone proves nothing.',
        'Roles decoded from a JWT read from storage are reported (the user can edit the stored token; the signature is only checked by the server).',
        'Guards built by factories (`roleGuard("admin")`) are analyzed only when the returned function is visible in the factory body.',
      ],
      falsePositives: [
        'Applications whose APIs enforce authorization server-side use guards purely for UX; suppress the finding with a justification referencing the server check.',
      ],
      remediation:
        "Keep guards for navigation UX, but derive roles from a server response (e.g. `/api/me`) held in memory, and make every API endpoint behind the guarded area enforce the same authorization on the server. Never accept roles or feature flags from URL parameters.",
      example: {
        unsafe: `export const adminGuard: CanActivateFn = () => localStorage.getItem('role') === 'admin';`,
        safe: `export const adminGuard: CanActivateFn = () =>
  inject(SessionService).me().pipe(map((me) => me.roles.includes('admin')));
// …and the /api/admin/** endpoints check the role on the server.`,
      },
      references: [
        { title: 'OWASP — Authorization Cheat Sheet (enforce on the server)', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html' },
        { title: 'Angular — Route guards', url: 'https://angular.dev/guide/routing/route-guards' },
      ],
    },
  },
  analyze(ctx) {
    const findings: RuleFinding[] = [];
    for (const fn of guardFunctions(ctx)) {
      const seen = new Set<string>();
      for (const d of decisions(ctx, fn)) {
        for (const op of operands(ctx, d)) {
          const result = ctx.taint.trace(op, { context: 'generic' });
          const flow: TaintFlow | undefined = result.flows.find((f) => CONTROLLABLE.has(f.source.kind));
          if (!flow) continue;
          const name = authzName([...result.names, ...words(op.getText()), flow.source.description.replace(/[^\w]+/g, ' ')].flatMap((n) => n.split(' ')));
          if (!name || seen.has(flow.source.description)) continue;
          seen.add(flow.source.description);
          findings.push({
            node: op,
            message: `Route guard decides access from '${name}' read from ${flow.source.description}, which the user can change; this is not access control unless the server enforces the same rule.`,
            confidence: lowerConfidence('medium', flow.approximations.length ? 1 : 0),
            evidenceKind: 'dataflow',
            trace: [...flow.steps, sinkStep(ctx, op, 'route guard decision')],
            evidence: [...flowEvidence(flow), `authorization-related name: ${name}`, 'server-side authorization: not visible (not assessed)'],
          });
        }
      }
    }
    return findings;
  },
});
