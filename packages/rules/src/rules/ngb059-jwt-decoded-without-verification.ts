import type * as ts from 'typescript';
import { defineRule, type AnalysisContext, type RuleFinding } from '@ngbastion/plugin-api';
import { memberName, strip } from '../shared/common.js';
import { objectLiteral, objectProp } from '../shared/http.js';
import { isServerFile, moduleCall } from '../shared/server.js';

const VERIFY = new Set(['verify', 'jwtVerify', 'compactVerify', 'flattenedVerify', 'generalVerify', 'verifyAsync', 'verifyIdToken', 'verifyAccessToken', 'verifyToken', 'verifyJwt']);
const PRIVILEGED = /\b(role|roles|admin|isAdmin|scope|scopes|permissions?|groups?|sub|userId|user_id|tenant|aud)\b/;

/** A JWT verification call in the same function (or module, for top-level code). */
function verifiedNearby(ctx: AnalysisContext, node: ts.Node): boolean {
  const t = ctx.ts;
  const scope: ts.Node = ctx.flow.enclosingFunction(node) ?? node.getSourceFile();
  let found = false;
  const visit = (n: ts.Node): void => {
    if (found) return;
    if (t.isCallExpression(n)) {
      const c = strip(ctx, n.expression);
      const name = t.isIdentifier(c) ? c.text : memberName(ctx, c);
      if (name && VERIFY.has(name)) found = true;
    }
    t.forEachChild(n, visit);
  };
  visit(scope);
  return found;
}

/** The decoded payload drives an authorization decision or becomes the request identity. */
function privilegedUse(ctx: AnalysisContext, call: ts.CallExpression): string | undefined {
  const t = ctx.ts;
  let p: ts.Node = call.parent;
  while (t.isParenthesizedExpression(p) || t.isAsExpression(p) || t.isNonNullExpression(p) || t.isAwaitExpression(p)) p = p.parent;
  const scope = ctx.flow.enclosingFunction(call) ?? call.getSourceFile();
  let name: string | undefined;
  if (t.isVariableDeclaration(p) && t.isIdentifier(p.name)) name = p.name.text;
  if (t.isVariableDeclaration(p) && t.isObjectBindingPattern(p.name)) {
    const keys = p.name.elements.map((e) => (e.propertyName ?? e.name).getText());
    const hit = keys.find((k) => PRIVILEGED.test(k));
    if (hit) return `claim '${hit}' is read from the unverified payload`;
  }
  if (t.isBinaryExpression(p) && p.operatorToken.kind === t.SyntaxKind.EqualsToken && /\b(req|request)\.(user|auth|claims|session)|res\.locals/.test(p.left.getText())) return `payload becomes ${p.left.getText()}`;
  if (t.isPropertyAccessExpression(p) && PRIVILEGED.test(p.name.text)) return `claim '${p.name.text}' is read from the unverified payload`;
  if (!name) return undefined;
  let use: string | undefined;
  const re = new RegExp(`\\b${name}\\??\\.(\\w+)`);
  const visit = (n: ts.Node): void => {
    if (use) return;
    if ((t.isIfStatement(n) || t.isConditionalExpression(n) || (t.isBinaryExpression(n) && /^(===|!==|==|!=|&&|\|\|)$/.test(n.operatorToken.getText())) || t.isCallExpression(n)) && re.test(n.getText())) {
      const claim = re.exec(n.getText())?.[1];
      if (claim && PRIVILEGED.test(claim)) use = `claim '${claim}' is checked from the unverified payload`;
    }
    if (t.isBinaryExpression(n) && n.operatorToken.kind === t.SyntaxKind.EqualsToken && /\b(req|request)\.(user|auth|claims)|res\.locals/.test(n.left.getText()) && new RegExp(`\\b${name}\\b`).test(n.right.getText())) use = `payload becomes ${n.left.getText()}`;
    t.forEachChild(n, visit);
  };
  visit(scope);
  return use;
}

export const ngb059 = defineRule({
  meta: {
    id: 'NGB059',
    name: 'JWT decoded without signature verification',
    category: 'ssr',
    defaultSeverity: 'high',
    cwe: ['CWE-347', 'CWE-345', 'CWE-287'],
    docs: {
      description:
        "Reports server-side code (SSR servers, API routes, BFFs) that decodes a JSON Web Token without verifying its signature — `jsonwebtoken` `jwt.decode()`, and `jose` `decodeJwt()` / `jwt-decode` in server files — when no verification call (`jwt.verify`, `jwtVerify`, `verifyIdToken`, …) exists in the same function. Also reports `jwt.verify()` configured to accept the `none` algorithm. Severity is high when the payload drives an authorization decision or becomes the request identity, medium otherwise.",
      rationale:
        "Decoding is Base64: anyone can create a token with `\"role\": \"admin\"`. Code that decodes a bearer token on the server and trusts its claims accepts forged identities. Decoding in the browser is fine (the client cannot be trusted anyway and the API verifies), which is why browser code is not reported.",
      patterns: [
        "`jwt.decode(token)` (`jsonwebtoken`, any import style) — server-only package, reported anywhere",
        "`decodeJwt(token)` (`jose`) and `jwtDecode(token)` (`jwt-decode`) in server files (`server.ts`, `*.server.ts`, files importing Node / Express modules)",
        "Not reported when the same function also calls a verification function (`verify`, `jwtVerify`, `compactVerify`, `verifyIdToken`, …) — e.g. decoding the header to look up a key",
        "`jwt.verify(token, key, { algorithms: ['none', …] })` — high",
        "High severity: claims such as `role`, `admin`, `scope`, `permissions`, `sub` used in conditions, or the payload assigned to `req.user` / `res.locals`",
      ],
      limitations: [
        'Verification performed by middleware before the handler (e.g. `express-jwt`) is not linked; such handlers are reported if they decode the token again themselves.',
        'Custom JWT parsing (`JSON.parse(atob(token.split(".")[1]))`) is not recognized.',
      ],
      falsePositives: [
        "Handlers behind a verifying gateway / middleware that only read display claims are reported with medium severity; prefer reading the claims the middleware attached (`req.auth`).",
      ],
      remediation:
        "Verify the token with the issuer's key and an explicit algorithm list (`jwt.verify(token, key, { algorithms: ['RS256'], audience, issuer })` or `jose.jwtVerify`) and use the claims from the verification result only. Never allow `none`.",
      example: {
        unsafe: `const claims = jwt.decode(req.headers.authorization!.slice(7)) as JwtPayload;
if (claims.role === 'admin') return next();`,
        safe: `const claims = jwt.verify(req.headers.authorization!.slice(7), publicKey, { algorithms: ['RS256'], audience: 'api' }) as JwtPayload;
if (claims.role === 'admin') return next();`,
      },
      references: [
        { title: 'jsonwebtoken — jwt.decode() does not verify the signature', url: 'https://github.com/auth0/node-jsonwebtoken#jwtdecodetoken--options' },
        { title: 'OWASP — JSON Web Token Cheat Sheet', url: 'https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html' },
      ],
    },
  },
  analyze(ctx) {
    const findings: RuleFinding[] = [];
    const server = new Map<ts.SourceFile, boolean>();
    const isServer = (n: ts.Node) => {
      const sf = n.getSourceFile();
      if (!server.has(sf)) server.set(sf, isServerFile(ctx, sf));
      return server.get(sf)!;
    };
    for (const call of ctx.index.calls) {
      const jsonwebtoken = moduleCall(ctx, call, ['jsonwebtoken'], ['decode', 'verify']);
      if (jsonwebtoken === 'verify') {
        const algs = objectProp(ctx, objectLiteral(ctx, call.arguments[2]), 'algorithms');
        const a = algs && strip(ctx, algs);
        if (a && ctx.ts.isArrayLiteralExpression(a) && a.elements.some((e) => ctx.symbols.constantString(e)?.toLowerCase() === 'none')) {
          findings.push({ node: algs!, message: "jwt.verify() accepts the 'none' algorithm: unsigned tokens pass verification.", confidence: 'high', severity: 'high', evidenceKind: 'pattern', evidence: ["algorithms includes 'none'"] });
        }
        continue;
      }
      const info = ctx.symbols.callee(call);
      const lib = jsonwebtoken ? 'jsonwebtoken'
        : moduleCall(ctx, call, ['jose'], ['decodeJwt']) ? 'jose'
        : info?.origin?.module === 'jwt-decode' && !info.declaration ? 'jwt-decode' : undefined;
      if (!lib || !call.arguments[0]) continue;
      if (lib !== 'jsonwebtoken' && !isServer(call)) continue;
      if (verifiedNearby(ctx, call)) continue;
      const use = privilegedUse(ctx, call);
      findings.push({
        node: call,
        message: `JWT payload is decoded with ${lib} without verifying the signature${use ? ` and ${use}` : ''}; anyone can forge these claims.`,
        confidence: use ? 'high' : 'medium',
        severity: use ? 'high' : 'medium',
        evidenceKind: 'pattern',
        evidence: [`${lib} decode in server code`, 'no verification call in the same function', ...(use ? [use] : [])],
      });
    }
    return findings;
  },
});
