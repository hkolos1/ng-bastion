import type * as ts from 'typescript';
import { defineRule, type AnalysisContext, type Confidence, type RuleFinding } from '@ngbastion/plugin-api';
import { enclosingClass, memberName, strip } from '../shared/common.js';

/** Node where the code asks for (`response_type=code`) or redeems (`grant_type=authorization_code`) an authorization code. */
interface OAuthStep {
  node: ts.Node;
  kind: 'exchange' | 'authorize';
}

function keyOf(ctx: AnalysisContext, n: ts.Node): string | undefined {
  const t = ctx.ts;
  if ((t.isPropertyAssignment(n) || t.isShorthandPropertyAssignment(n)) && (t.isIdentifier(n.name) || t.isStringLiteralLike(n.name))) return n.name.text;
  return undefined;
}

function steps(ctx: AnalysisContext): OAuthStep[] {
  const t = ctx.ts;
  const out: OAuthStep[] = [];
  for (const sf of ctx.sourceFiles) {
    const visit = (n: ts.Node): void => {
      if (t.isPropertyAssignment(n)) {
        const k = keyOf(ctx, n);
        const v = ctx.symbols.constantString(n.initializer);
        if ((k === 'grant_type' || k === 'grantType') && v === 'authorization_code') out.push({ node: n, kind: 'exchange' });
        // Protocol parameter objects use the wire names; camelCase objects are library configs (which add state themselves).
        if (k === 'response_type' && v === 'code' && t.isObjectLiteralExpression(n.parent)
          && n.parent.properties.some((p) => /^(client_id|redirect_uri)$/.test(keyOf(ctx, p) ?? ''))) out.push({ node: n.parent, kind: 'authorize' });
      }
      if (t.isCallExpression(n) && ['set', 'append'].includes(memberName(ctx, n.expression) ?? '') && n.arguments[1]) {
        const k = ctx.symbols.constantString(n.arguments[0]!);
        const v = ctx.symbols.constantString(n.arguments[1]);
        if (k === 'grant_type' && v === 'authorization_code') out.push({ node: n, kind: 'exchange' });
        if (k === 'response_type' && v === 'code') out.push({ node: n, kind: 'authorize' });
      }
      if ((t.isStringLiteralLike(n) || t.isTemplateHead(n) || t.isTemplateMiddle(n) || t.isTemplateTail(n))) {
        if (/grant_type=authorization_code/.test(n.text)) out.push({ node: n, kind: 'exchange' });
        if (/response_type=code(&|$)/.test(n.text)) out.push({ node: n, kind: 'authorize' });
      }
      t.forEachChild(n, visit);
    };
    visit(sf);
  }
  return out;
}

const STATE_CONTAINER = /(query|param|search|callback|response|url|hash|fragment|result|args)/i;

/** Facts about `state` handling within a scope (class or file). */
function stateFacts(ctx: AnalysisContext, scope: ts.Node) {
  const t = ctx.ts;
  let read = false;
  let compared = false;
  let sent = false;
  let pkce = false;
  const mentionsState = (e: ts.Node) => /(^|[^\w])state\b|State\b|'state'|"state"/.test(e.getText()) && !/\b(router|history|store|ngrx|routerState)\b/i.test(e.getText());
  const visit = (n: ts.Node): void => {
    if (t.isCallExpression(n) && n.arguments[0]) {
      const m = memberName(ctx, n.expression);
      const k = ctx.symbols.constantString(n.arguments[0]);
      if ((m === 'get' || m === 'getAll') && k === 'state') read = true;
      if ((m === 'set' || m === 'append') && k === 'state') sent = true;
      if ((m === 'set' || m === 'append') && (k === 'code_verifier' || k === 'code_challenge')) pkce = true;
    }
    if (t.isElementAccessExpression(n) && ctx.symbols.constantString(n.argumentExpression) === 'state') read = true;
    if (t.isPropertyAccessExpression(n) && n.name.text === 'state' && STATE_CONTAINER.test(n.expression.getText())) read = true;
    if (t.isBindingElement(n) && (n.propertyName ?? n.name).getText() === 'state' && t.isObjectBindingPattern(n.parent)
      && n.parent.elements.some((e) => (e.propertyName ?? e.name).getText() === 'code')) read = true;
    const key = keyOf(ctx, n);
    if (key === 'state') sent = true;
    if (key && /^(code_verifier|codeVerifier|code_challenge|codeChallenge)$/.test(key)) pkce = true;
    if ((t.isStringLiteralLike(n) || t.isTemplateHead(n) || t.isTemplateMiddle(n) || t.isTemplateTail(n))) {
      if (/[?&]state=/.test(n.text)) sent = true;
      if (/code_(verifier|challenge)=/.test(n.text)) pkce = true;
    }
    if (t.isBinaryExpression(n) && [t.SyntaxKind.EqualsEqualsEqualsToken, t.SyntaxKind.ExclamationEqualsEqualsToken, t.SyntaxKind.EqualsEqualsToken, t.SyntaxKind.ExclamationEqualsToken].includes(n.operatorToken.kind)
      && (mentionsState(n.left) || mentionsState(n.right))) compared = true;
    t.forEachChild(n, visit);
  };
  visit(scope);
  return { read, compared, sent, pkce };
}

export const ngb023 = defineRule({
  meta: {
    id: 'NGB023',
    name: 'Missing OAuth state validation',
    category: 'navigation-auth',
    defaultSeverity: 'high',
    cwe: ['CWE-352', 'CWE-345'],
    docs: {
      description:
        "Reports hand-written OAuth 2.0 / OpenID Connect authorization-code flows in which the callback redeems the `code` (`grant_type=authorization_code`) without reading and comparing the `state` parameter, and authorization requests (`response_type=code`) that do not send a `state`. The analysis looks at the class (or file) that performs the exchange. When the exchange sends a PKCE `code_verifier`, confidence is lowered because PKCE also binds the code to the browser session.",
      rationale:
        "Without `state`, an attacker can complete their own authorization flow up to the callback and make the victim's browser load `/callback?code=<attacker's code>`: the victim is then signed in to the attacker's account (login CSRF), or the attacker's account gets linked to the victim's profile. `state` (or PKCE) ties the response to the request that this browser started.",
      patterns: [
        "Exchange: `{ grant_type: 'authorization_code', … }`, `params.set('grant_type', 'authorization_code')`, or `'grant_type=authorization_code'` in a request body string",
        "Authorization request: `response_type=code` in a URL string, `{ response_type: 'code', client_id, … }` (wire parameter names; camelCase library configs are ignored), `params.set('response_type', 'code')`",
        "`state` read: `queryParamMap.get('state')`, `searchParams.get('state')`, `params['state']`, `params.state`, `const { code, state } = …`",
        '`state` validated: an equality comparison involving a `state` value in the same class/file',
        'PKCE: `code_verifier` sent with the exchange (confidence lowered to low)',
      ],
      limitations: [
        'Flows handled by OAuth libraries (angular-oauth2-oidc, angular-auth-oidc-client, MSAL) are not analyzed here; those libraries validate `state` themselves (see NGB024 for settings that weaken them).',
        'State handling spread over several services (callback parsing in one class, comparison in another) can be missed when the exchange class neither reads nor compares the parameter.',
        'Whether the stored state is unguessable and single-use is not assessed.',
      ],
      falsePositives: [
        'Backends-for-frontend that validate `state` on the server while the SPA only forwards the code can be reported; suppress with a justification.',
      ],
      remediation:
        "Generate a random `state` (`crypto.getRandomValues`) per authorization request, store it in `sessionStorage`, send it, and in the callback reject the response unless the returned `state` equals the stored value, then delete it. Prefer a maintained OIDC client library, and use PKCE (S256) in addition.",
      example: {
        unsafe: `const code = this.route.snapshot.queryParamMap.get('code')!;
this.http.post(TOKEN_URL, { grant_type: 'authorization_code', code, redirect_uri, client_id });`,
        safe: `const q = this.route.snapshot.queryParamMap;
if (q.get('state') !== sessionStorage.getItem('oauth_state')) throw new Error('state mismatch');
this.http.post(TOKEN_URL, { grant_type: 'authorization_code', code: q.get('code'), code_verifier, redirect_uri, client_id });`,
      },
      references: [
        { title: 'RFC 6749 §10.12 — Cross-Site Request Forgery', url: 'https://www.rfc-editor.org/rfc/rfc6749#section-10.12' },
        { title: 'RFC 9700 — OAuth 2.0 Security Best Current Practice (CSRF protection)', url: 'https://www.rfc-editor.org/rfc/rfc9700#section-4.7' },
      ],
    },
  },
  analyze(ctx) {
    const findings: RuleFinding[] = [];
    const reported = new Set<ts.Node>();
    for (const step of steps(ctx)) {
      const scope: ts.Node = enclosingClass(ctx, step.node) ?? step.node.getSourceFile();
      if (step.kind === 'exchange' && reported.has(scope)) continue;
      const facts = stateFacts(ctx, scope);
      if (step.kind === 'exchange') {
        if (facts.compared) continue;
        reported.add(scope);
        let confidence: Confidence = facts.read ? 'low' : 'medium';
        if (facts.pkce) confidence = 'low';
        findings.push({
          node: strip(ctx, step.node as ts.Expression),
          message: facts.read
            ? 'Authorization code is redeemed, but the returned OAuth state parameter is never compared with the value this browser stored; login CSRF / account linking attacks are possible.'
            : 'Authorization code is redeemed without validating the OAuth state parameter; an attacker can make the victim sign in with the attacker\'s authorization code (login CSRF).',
          confidence,
          evidenceKind: 'pattern',
          evidence: [
            'grant_type=authorization_code exchange',
            facts.read ? 'state is read but not compared in this class/file' : 'no read of the state parameter in this class/file',
            facts.pkce ? 'PKCE code_verifier is sent (mitigates code injection; state is still recommended)' : 'no PKCE code_verifier sent with the exchange',
          ],
        });
      } else if (!facts.sent) {
        findings.push({
          node: step.node,
          message: 'OAuth authorization request (response_type=code) is built without a state parameter; the callback cannot tell whether this browser started the flow.',
          confidence: facts.pkce ? 'low' : 'medium',
          severity: 'medium',
          evidenceKind: 'pattern',
          evidence: ['response_type=code request', 'no state parameter set in this class/file', ...(facts.pkce ? ['PKCE is used'] : [])],
        });
      }
    }
    return findings;
  },
});
