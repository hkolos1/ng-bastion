import type * as ts from 'typescript';
import { defineRule, type AnalysisContext, type Confidence, type RuleFinding } from '@ngbastion/plugin-api';
import { memberName, receiverOf, strip } from '../shared/common.js';
import { words } from '../shared/sensitivity.js';

/** OIDC client libraries whose `getIdToken()` returns the OpenID Connect ID token. */
const OIDC_LIBRARIES = ['angular-oauth2-oidc', 'angular-auth-oidc-client', 'oidc-client-ts', 'oidc-client', '@auth0/auth0-angular', '@auth0/auth0-spa-js', 'keycloak-js', 'keycloak-angular', '@azure/msal-browser', '@azure/msal-angular'];
/** Ecosystems where sending the ID token to your own backend is the documented design. */
const ID_TOKEN_BACKENDS = /firebase|@angular\/fire|cognito|amplify|google-auth-library|gapi/i;

function isIdTokenName(name: string): boolean {
  const w = words(name);
  for (let i = 0; i < w.length - 1; i++) if (w[i] === 'id' && w[i + 1] === 'token' && !['claims', 'hint', 'payload', 'expiration', 'exp', 'header'].includes(w[i + 2] ?? '')) return true;
  return w.includes('idtoken') && !w.includes('claims');
}

interface Evidence { confidence: Confidence; why: string }

function idTokenEvidence(ctx: AnalysisContext, value: ts.Expression): Evidence | undefined {
  const t = ctx.ts;
  let best: Evidence | undefined;
  let excluded = false;
  const visit = (n: ts.Node): void => {
    if (t.isCallExpression(n)) {
      const info = ctx.symbols.callee(n);
      const name = info?.name ?? memberName(ctx, n.expression);
      if (name === 'getIdToken') {
        const mod = info?.receiver?.module ?? info?.origin?.module ?? '';
        const recvText = receiverOf(ctx, n.expression) ? strip(ctx, receiverOf(ctx, n.expression)!).getText() : '';
        if (ID_TOKEN_BACKENDS.test(mod) || ID_TOKEN_BACKENDS.test(recvText) || /\b(currentUser|user)$/.test(recvText) && !OIDC_LIBRARIES.includes(mod)) excluded = true;
        else if (OIDC_LIBRARIES.includes(mod)) best = { confidence: 'high', why: `${recvText || 'client'}.getIdToken() from ${mod}` };
        else best ??= { confidence: 'medium', why: `${recvText || ''}.getIdToken()` };
      }
    }
    if ((t.isIdentifier(n) || t.isPrivateIdentifier(n)) && isIdTokenName(n.text) && !best) best = { confidence: 'medium', why: `value named '${n.text}'` };
    if (t.isStringLiteralLike(n) && /^id_?token$/i.test(n.text) && t.isElementAccessExpression(n.parent) && !best) best = { confidence: 'medium', why: `value read from key '${n.text}'` };
    t.forEachChild(n, visit);
  };
  visit(value);
  if (excluded) return undefined;
  if (!best) {
    const names = ctx.taint.trace(value, { context: 'generic' }).names.filter(isIdTokenName);
    if (names.length) best = { confidence: 'low', why: `data flow passes through '${names[0]}'` };
  }
  if (best) {
    const text = value.getText();
    if (ID_TOKEN_BACKENDS.test(text)) return undefined;
  }
  return best;
}

export const ngb058 = defineRule({
  meta: {
    id: 'NGB058',
    name: 'ID token sent as API bearer token',
    category: 'navigation-auth',
    defaultSeverity: 'medium',
    cwe: ['CWE-287', 'CWE-863'],
    docs: {
      description:
        "Reports `Authorization` headers whose value is an OpenID Connect ID token: `getIdToken()` of an OIDC client library (angular-oauth2-oidc, angular-auth-oidc-client, oidc-client-ts, Auth0, Keycloak, MSAL — high confidence), or values named `idToken` / `id_token` (medium; low when the name only appears along the traced data flow). Firebase, Amplify / Cognito and Google identity tokens, which those platforms are designed to send to your backend, are not reported.",
      rationale:
        "An ID token tells the client who signed in; its audience is the client application, not your API. An API that accepts ID tokens as bearer tokens cannot tell which client a token was issued to (any app of the same identity provider gets valid ID tokens for its users), has no scopes to authorize against, and usually accepts tokens with a longer lifetime that are logged and stored more freely. OAuth 2.0 access tokens — audience-restricted to the API — exist for this.",
      patterns: [
        "Header values: `{ Authorization: `Bearer ${v}` }` in `HttpHeaders`, `setHeaders`, Fetch / Axios options; `headers.set('Authorization', v)` / `.append(…)`",
        '`v` contains `oauthService.getIdToken()` (OIDC client library) → high',
        '`v` is or contains an identifier / key named `idToken`, `id_token`, `IdToken` → medium; only along the traced flow → low',
        'Excluded: Firebase / AngularFire `user.getIdToken()`, Amplify / Cognito, Google auth libraries',
      ],
      limitations: [
        'Tokens stored under a generic name (`token`) are not recognized as ID tokens.',
        'Whether the backend validates the audience is not visible; a backend that only accepts its own ID tokens (same client) is not exploitable through other clients.',
      ],
      falsePositives: [
        'Backends designed around ID tokens of their own client (some Google Cloud and serverless setups) are reported; document an exception.',
      ],
      remediation:
        'Request an access token for the API (an `audience` / resource scope) and send `getAccessToken()` instead. Have the API validate the token audience. Keep the ID token in the client for display and session information only.',
      example: {
        unsafe: "req.clone({ setHeaders: { Authorization: `Bearer ${this.oauth.getIdToken()}` } })",
        safe: "req.clone({ setHeaders: { Authorization: `Bearer ${this.oauth.getAccessToken()}` } })",
      },
      references: [
        { title: 'OAuth 2.0 Security Best Current Practice (RFC 9700) — Access token audience restriction', url: 'https://www.rfc-editor.org/rfc/rfc9700#section-2.3' },
        { title: 'Auth0 — ID Tokens vs Access Tokens', url: 'https://auth0.com/docs/secure/tokens/id-tokens#id-token-and-access-token' },
        { title: 'OpenID Connect Core 1.0 — ID Token (aud claim)', url: 'https://openid.net/specs/openid-connect-core-1_0.html#IDToken' },
      ],
    },
  },
  analyze(ctx) {
    const t = ctx.ts;
    const findings: RuleFinding[] = [];
    const seen = new Set<ts.Node>();
    const report = (node: ts.Node, value: ts.Expression) => {
      if (seen.has(value)) return;
      seen.add(value);
      const ev = idTokenEvidence(ctx, value);
      if (!ev) return;
      findings.push({
        node,
        message: `An OpenID Connect ID token is sent as the API bearer token (${ev.why}); APIs should receive access tokens issued for them.`,
        confidence: ev.confidence,
        evidenceKind: ev.confidence === 'low' ? 'heuristic' : 'pattern',
        evidence: [ev.why, 'Authorization header'],
      });
    };
    const isAuthKey = (s: string | undefined) => !!s && /^authorization$/i.test(s);
    const visit = (n: ts.Node): void => {
      if (t.isPropertyAssignment(n) && n.name && (t.isIdentifier(n.name) || t.isStringLiteralLike(n.name)) && isAuthKey(n.name.text)) report(n, n.initializer);
      if (t.isCallExpression(n) && ['set', 'append'].includes(memberName(ctx, n.expression) ?? '') && n.arguments.length >= 2 && isAuthKey(ctx.symbols.constantString(n.arguments[0]!))) report(n, n.arguments[1]!);
      t.forEachChild(n, visit);
    };
    for (const sf of ctx.sourceFiles) if (!sf.fileName.endsWith('.json')) visit(sf);
    return findings;
  },
});
