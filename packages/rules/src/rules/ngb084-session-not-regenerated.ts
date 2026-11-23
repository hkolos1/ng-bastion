import type * as ts from 'typescript';
import { defineRule, type AnalysisContext, type RuleFinding } from '@ngbastion/plugin-api';
import { memberName, receiverOf, strip } from '../shared/common.js';
import { isServerRequest } from '../shared/server.js';

/** Session properties that mark a session as authenticated. */
const AUTH_PROPS = /^(user|userId|user_id|uid|username|account|accountId|authenticated|isAuthenticated|auth|loggedIn|isLoggedIn|login|principal|identity|role|roles|isAdmin)$/i;

function falsy(ctx: AnalysisContext, e: ts.Expression): boolean {
  const t = ctx.ts;
  const x = strip(ctx, e);
  return x.kind === t.SyntaxKind.NullKeyword || x.kind === t.SyntaxKind.FalseKeyword || (t.isIdentifier(x) && x.text === 'undefined') || (t.isVoidExpression(x));
}

/** Outermost function (route handler) containing the node. */
function handlerOf(ctx: AnalysisContext, node: ts.Node): ts.Node {
  let outer: ts.Node = node.getSourceFile();
  for (let n: ts.Node | undefined = node.parent; n; n = n.parent) {
    if (ctx.ts.isFunctionLike(n)) outer = n;
    if (ctx.ts.isSourceFile(n)) break;
  }
  return outer;
}

function callsRegenerate(ctx: AnalysisContext, scope: ts.Node): boolean {
  const t = ctx.ts;
  let found = false;
  const visit = (n: ts.Node): void => {
    if (found) return;
    if (t.isCallExpression(n) && memberName(ctx, n.expression) === 'regenerate') found = true;
    t.forEachChild(n, visit);
  };
  visit(scope);
  return found;
}

export const ngb084 = defineRule({
  meta: {
    id: 'NGB084',
    name: 'Session not regenerated after login',
    category: 'ssr',
    defaultSeverity: 'medium',
    cwe: ['CWE-384'],
    docs: {
      description:
        "Reports server-side session stores (`express-session` style `req.session`) that are marked as authenticated — `req.session.user = …`, `req.session.userId = …`, `req.session.authenticated = true` — in a request handler that never calls `req.session.regenerate()`. Heuristic: the property names identify a login.",
      rationale:
        "Session fixation: if the session ID stays the same across login, an attacker who planted or learned the pre-login session ID (shared computer, a subdomain that can set cookies, a session ID in a URL) is logged in as the victim as soon as the victim authenticates. Issuing a new session ID at the privilege change closes that. `express-session` does not do this automatically.",
      patterns: [
        '`req.session.<user | userId | uid | account | authenticated | loggedIn | principal | role | isAdmin …> = value` on an Express / Node request (typed, or untyped `req` next to `res`)',
        'Safe: a `regenerate()` call anywhere in the same handler, including the assignment inside the `req.session.regenerate(cb)` callback',
        'Assignments of `null`, `undefined`, `false` (logout) are ignored',
      ],
      limitations: [
        'Regeneration performed in a helper or middleware outside the handler is not seen.',
        'Session libraries with other APIs (Fastify `request.session.set()`, `cookie-session`, JWTs) are not analyzed; `cookie-session` stores data client-side and is not subject to fixation in the same way.',
        'Passport ≥ 0.6 regenerates sessions in `req.login()`; code that only calls `req.login()` is not reported.',
      ],
      falsePositives: [
        'Updating profile data on an already authenticated session (`req.session.user = updatedUser`) is reported; such handlers are not logins — suppress them inline.',
      ],
      remediation:
        "Regenerate the session when the user logs in (and when privileges change): `req.session.regenerate(err => { if (err) return next(err); req.session.user = user.id; req.session.save(() => res.redirect('/')); });`.",
      example: {
        unsafe: "app.post('/login', async (req, res) => {\n  const user = await auth(req.body);\n  req.session.userId = user.id;\n  res.redirect('/');\n});",
        safe: "app.post('/login', async (req, res, next) => {\n  const user = await auth(req.body);\n  req.session.regenerate((err) => {\n    if (err) return next(err);\n    req.session.userId = user.id;\n    res.redirect('/');\n  });\n});",
      },
      references: [
        { title: 'OWASP — Session Management Cheat Sheet (renew the session ID after privilege changes)', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#renew-the-session-id-after-any-privilege-level-change' },
        { title: 'express-session — Session.regenerate()', url: 'https://github.com/expressjs/session#sessionregeneratecallback' },
      ],
    },
  },
  analyze(ctx) {
    const findings: RuleFinding[] = [];
    const checked = new Map<ts.Node, boolean>();
    for (const a of ctx.index.assignments) {
      if (a.operatorToken.kind !== ctx.ts.SyntaxKind.EqualsToken || falsy(ctx, a.right)) continue;
      const left = strip(ctx, a.left);
      const prop = memberName(ctx, left);
      if (!prop || !AUTH_PROPS.test(prop)) continue;
      const session = receiverOf(ctx, left);
      if (!session || memberName(ctx, session) !== 'session') continue;
      const req = receiverOf(ctx, strip(ctx, session));
      if (!req || !isServerRequest(ctx, req)) continue;
      const handler = handlerOf(ctx, a);
      let regenerates = checked.get(handler);
      if (regenerates === undefined) checked.set(handler, (regenerates = callsRegenerate(ctx, handler)));
      if (regenerates) continue;
      findings.push({
        node: a,
        message: `The session is marked as authenticated (session.${prop}) without regenerating the session ID; an attacker who fixed the pre-login session ID inherits the login.`,
        confidence: 'medium',
        evidenceKind: 'heuristic',
        evidence: [`login inferred from session property '${prop}'`, 'no regenerate() call in the handler'],
      });
    }
    return findings;
  },
});
