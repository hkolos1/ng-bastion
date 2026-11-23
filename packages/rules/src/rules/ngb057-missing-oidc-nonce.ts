import type * as ts from 'typescript';
import { defineRule, type AnalysisContext, type RuleFinding } from '@ngbastion/plugin-api';
import { is, memberName, strip } from '../shared/common.js';
import { objectLiteral, objectProp } from '../shared/http.js';

const LOGIN_METHODS = new Set(['tryLogin', 'tryLoginImplicitFlow', 'tryLoginCodeFlow', 'loadDiscoveryDocumentAndTryLogin', 'loadDiscoveryDocumentAndLogin']);
const ID_TOKEN_RESPONSE = /(^|[?&])response_type=[^&#]*id_token/i;

/** Literal text of a URL built with a template literal or `+` concatenation (dynamic parts become `\u0000`). */
function literalText(ctx: AnalysisContext, e: ts.Expression): string | undefined {
  const t = ctx.ts;
  const x = strip(ctx, e);
  if (t.isStringLiteralLike(x)) return x.text;
  if (t.isTemplateExpression(x)) return x.head.text + x.templateSpans.map((s) => `\0${s.literal.text}`).join('');
  if (t.isBinaryExpression(x) && x.operatorToken.kind === t.SyntaxKind.PlusToken) return (literalText(ctx, x.left) ?? '\0') + (literalText(ctx, x.right) ?? '\0');
  return undefined;
}

export const ngb057 = defineRule({
  meta: {
    id: 'NGB057',
    name: 'Missing OIDC nonce',
    category: 'navigation-auth',
    defaultSeverity: 'medium',
    cwe: ['CWE-294', 'CWE-345'],
    docs: {
      description:
        "Reports OpenID Connect sign-ins that do not bind the ID token to the browser session with a `nonce`: angular-oauth2-oidc login calls with `disableNonceCheck: true`, and hand-written authorization requests that ask for an `id_token` from the authorization endpoint (implicit / hybrid flow) without a `nonce` parameter — in URL strings and in `response_type` request objects.",
      rationale:
        "When the ID token is returned from the authorization endpoint, the `nonce` is the only thing that ties it to the sign-in this browser started. Without it, an ID token stolen from logs, history or another client — or injected by an attacker into the redirect — is accepted, and the attacker can sign the victim into the attacker's account or replay a victim's token. OpenID Connect Core makes `nonce` mandatory for these flows.",
      patterns: [
        "angular-oauth2-oidc: `tryLogin({ disableNonceCheck: true })`, `tryLoginImplicitFlow(…)`, `loadDiscoveryDocumentAndTryLogin(…)`, `loadDiscoveryDocumentAndLogin(…)` — high confidence when the receiver is `OAuthService`",
        "URLs (string, template literal, concatenation) containing `response_type=…id_token…` without `nonce=`",
        "Object literals with `response_type: 'id_token…'` that also carry `client_id` / `redirect_uri` and no `nonce` property (e.g. `new URLSearchParams({ … })`)",
        "The authorization code flow (`response_type=code`) is not reported: PKCE protects the code and the token is fetched from the token endpoint",
      ],
      limitations: [
        "Validation of the returned `nonce` claim in hand-written callbacks is not checked; only whether one is sent.",
        "Library configurations (angular-oauth2-oidc `AuthConfig`, angular-auth-oidc-client) generate nonces themselves and are not reported unless the check is explicitly disabled.",
      ],
      falsePositives: [
        "Requests whose `nonce` parameter is appended later by another helper are reported; build the request in one place.",
      ],
      remediation:
        "Use the authorization code flow with PKCE (`responseType: 'code'`). If ID tokens must come from the authorization endpoint, send a fresh random `nonce` (`crypto.randomUUID()`), keep it in session storage, and reject ID tokens whose `nonce` claim differs. Never set `disableNonceCheck`.",
      example: {
        unsafe: "location.assign(`${issuer}/authorize?client_id=${id}&response_type=id_token&redirect_uri=${cb}&state=${state}`);",
        safe: "location.assign(`${issuer}/authorize?client_id=${id}&response_type=code&redirect_uri=${cb}&state=${state}&code_challenge=${challenge}&code_challenge_method=S256`);",
      },
      references: [
        { title: 'OpenID Connect Core 1.0 — Nonce (implicit flow)', url: 'https://openid.net/specs/openid-connect-core-1_0.html#ImplicitAuthRequest' },
        { title: 'angular-oauth2-oidc — LoginOptions.disableNonceCheck', url: 'https://manfredsteyer.github.io/angular-oauth2-oidc/docs/classes/LoginOptions.html' },
      ],
    },
  },
  analyze(ctx) {
    const t = ctx.ts;
    const findings: RuleFinding[] = [];

    for (const call of ctx.index.calls) {
      const m = memberName(ctx, call.expression);
      if (!m || !LOGIN_METHODS.has(m)) continue;
      const info = ctx.symbols.callee(call);
      if (info?.declaration) continue;
      const certain = is(info?.receiver, 'angular-oauth2-oidc', 'OAuthService');
      if (info?.receiver && !certain) continue;
      const flag = objectProp(ctx, objectLiteral(ctx, call.arguments[0]), 'disableNonceCheck');
      if (!flag || strip(ctx, flag).kind !== t.SyntaxKind.TrueKeyword) continue;
      findings.push({
        node: flag,
        message: `${m}({ disableNonceCheck: true }) accepts ID tokens that were not issued for this sign-in; injected or replayed ID tokens are not detected.`,
        confidence: certain ? 'high' : 'medium',
        severity: 'medium',
        evidenceKind: 'pattern',
        evidence: [certain ? 'receiver: OAuthService (angular-oauth2-oidc)' : 'receiver type not resolved; matched by method and option name', 'disableNonceCheck: true'],
      });
    }

    const visit = (n: ts.Node): void => {
      const parentIsConcat = n.parent && t.isBinaryExpression(n.parent) && n.parent.operatorToken.kind === t.SyntaxKind.PlusToken;
      if ((t.isStringLiteralLike(n) || t.isTemplateExpression(n) || (t.isBinaryExpression(n) && n.operatorToken.kind === t.SyntaxKind.PlusToken)) && !parentIsConcat && !t.isTemplateSpan(n.parent) && !t.isImportDeclaration(n.parent)) {
        const text = literalText(ctx, n as ts.Expression);
        if (text && ID_TOKEN_RESPONSE.test(text) && !/[?&]nonce=/i.test(text)) {
          findings.push({
            node: n,
            message: 'Authorization request asks for an id_token without a nonce parameter; the returned ID token is not bound to this sign-in.',
            confidence: /[?&]client_id=|\/authori[sz]e/i.test(text) ? 'high' : 'medium',
            severity: 'medium',
            evidenceKind: 'pattern',
            evidence: [`response_type: ${/response_type=([^&#\0]*)/i.exec(text)?.[1] ?? '?'}`, 'no nonce= parameter in the request URL'],
          });
        }
        return;
      }
      if (t.isObjectLiteralExpression(n)) {
        const rt = objectProp(ctx, n, 'response_type');
        const rtv = rt && ctx.symbols.constantString(rt);
        if (rtv && /\bid_token\b/.test(rtv) && (objectProp(ctx, n, 'client_id') || objectProp(ctx, n, 'redirect_uri')) && !objectProp(ctx, n, 'nonce')) {
          findings.push({
            node: rt,
            message: `Authorization request with response_type '${rtv}' has no nonce; the returned ID token is not bound to this sign-in.`,
            confidence: 'high',
            severity: 'medium',
            evidenceKind: 'pattern',
            evidence: [`response_type: ${rtv}`, 'no nonce property in the request parameters'],
          });
        }
      }
      t.forEachChild(n, visit);
    };
    for (const sf of ctx.sourceFiles) if (!sf.fileName.endsWith('.json')) visit(sf);
    return findings;
  },
});
