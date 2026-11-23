import type * as ts from 'typescript';
import { defineRule, type AnalysisContext, type Confidence, type RuleFinding, type Severity } from '@ngbastion/plugin-api';
import { is, strip, codeFiles } from '../shared/common.js';

const CONFIG_KEYS = /^(issuer|authority|clientId|client_id|redirectUri|redirect_uri|loginUrl|tokenEndpoint|postLogoutRedirectUri)$/;

interface Weakening {
  /** Property name. */
  key: string;
  matches: (value: string | boolean | undefined) => boolean;
  severity: Severity;
  confidence: Confidence;
  message: string;
}

const WEAKENINGS: Weakening[] = [
  { key: 'disablePKCE', matches: (v) => v === true, severity: 'high', confidence: 'high', message: 'PKCE is disabled (disablePKCE: true); intercepted authorization codes can be redeemed by an attacker.' },
  { key: 'disablePkce', matches: (v) => v === true, severity: 'high', confidence: 'high', message: 'PKCE is disabled; intercepted authorization codes can be redeemed by an attacker.' },
  { key: 'code_challenge_method', matches: (v) => typeof v === 'string' && v.toLowerCase() === 'plain', severity: 'high', confidence: 'high', message: "PKCE uses the 'plain' challenge method; the challenge equals the verifier, so anyone who sees the authorization request can redeem the code. Use S256." },
  { key: 'codeChallengeMethod', matches: (v) => typeof v === 'string' && v.toLowerCase() === 'plain', severity: 'high', confidence: 'high', message: "PKCE uses the 'plain' challenge method; use S256." },
  { key: 'responseType', matches: (v) => typeof v === 'string' && /\btoken\b/.test(v) && !/\bcode\b/.test(v), severity: 'high', confidence: 'high', message: 'OAuth implicit flow (responseType returns tokens from the authorization endpoint); access tokens travel in the URL fragment and cannot be sender-constrained. Use the authorization code flow with PKCE.' },
  { key: 'response_type', matches: (v) => typeof v === 'string' && /\btoken\b/.test(v) && !/\bcode\b/.test(v), severity: 'high', confidence: 'high', message: 'OAuth implicit flow (response_type returns tokens from the authorization endpoint); use the authorization code flow with PKCE.' },
  { key: 'skipIssuerCheck', matches: (v) => v === true, severity: 'medium', confidence: 'high', message: 'Issuer validation of the discovery document / ID token is disabled (skipIssuerCheck: true); tokens from a different issuer are accepted.' },
  { key: 'requireHttps', matches: (v) => v === false, severity: 'medium', confidence: 'high', message: 'requireHttps: false allows the identity provider and its endpoints over plain HTTP; tokens can be intercepted or tampered with in transit.' },
  { key: 'disableAtHashCheck', matches: (v) => v === true, severity: 'low', confidence: 'medium', message: 'at_hash validation is disabled (disableAtHashCheck: true); a substituted access token is not detected in implicit/hybrid flows.' },
  { key: 'strictDiscoveryDocumentValidation', matches: (v) => v === false, severity: 'low', confidence: 'medium', message: 'Strict discovery-document validation is disabled; endpoints on other hosts than the issuer are accepted.' },
  { key: 'skipSubjectCheck', matches: (v) => v === true, severity: 'low', confidence: 'medium', message: 'Subject check on token refresh is disabled (skipSubjectCheck: true); a refresh can silently switch to another user.' },
  { key: 'disableIdTokenValidation', matches: (v) => v === true, severity: 'high', confidence: 'high', message: 'ID token validation is disabled (disableIdTokenValidation: true); forged or replayed ID tokens are accepted by the client.' },
  { key: 'disableIatOffsetValidation', matches: (v) => v === true, severity: 'low', confidence: 'medium', message: 'ID token issued-at validation is disabled; old (replayed) ID tokens are accepted.' },
];

function value(ctx: AnalysisContext, e: ts.Expression): string | boolean | undefined {
  const x = strip(ctx, e);
  if (x.kind === ctx.ts.SyntaxKind.TrueKeyword) return true;
  if (x.kind === ctx.ts.SyntaxKind.FalseKeyword) return false;
  return ctx.symbols.constantString(x);
}

/** angular-oauth2-oidc `AuthConfig` literal (typed or `new AuthConfig({...})`). */
function isOAuth2OidcConfig(ctx: AnalysisContext, obj: ts.ObjectLiteralExpression): boolean {
  const t = ctx.ts;
  const p = obj.parent;
  if (t.isNewExpression(p) && is(ctx.symbols.typeOrigin(p.expression), 'angular-oauth2-oidc', 'AuthConfig')) return true;
  if ((t.isVariableDeclaration(p) || t.isPropertyDeclaration(p)) && p.type && t.isTypeReferenceNode(p.type) && p.type.typeName.getText() === 'AuthConfig') {
    const o = ctx.symbols.typeOrigin(p.name as ts.Identifier);
    return !o || is(o, 'angular-oauth2-oidc');
  }
  return false;
}

export const ngb024 = defineRule({
  meta: {
    id: 'NGB024',
    name: 'Weakened OAuth/OIDC client configuration',
    category: 'navigation-auth',
    defaultSeverity: 'high',
    cwe: ['CWE-287', 'CWE-345'],
    docs: {
      description:
        "Reports OAuth 2.0 / OpenID Connect client configuration that explicitly switches off a protection: PKCE disabled or using the `plain` challenge method, the implicit flow (`responseType` returning tokens), disabled issuer / ID-token / at_hash / subject checks, and `requireHttps: false`. Covers configuration objects for angular-oauth2-oidc (`AuthConfig`), angular-auth-oidc-client (`OpenIdConfiguration`) and hand-written client settings.",
      rationale:
        'OIDC client libraries are secure by default; these settings exist for legacy providers and debugging and are easy to leave in production. Without PKCE an intercepted authorization code (logs, referrers, malicious redirect handlers) can be redeemed; the implicit flow exposes access tokens in the URL; disabled ID-token validation lets forged or replayed tokens sign users in.',
      patterns: [
        'Object literals that look like an OAuth client config (contain `issuer`, `authority`, `clientId`, `client_id`, `redirectUri`, `loginUrl`, `tokenEndpoint` …)',
        '`disablePKCE: true` / `disablePkce: true`, `code_challenge_method: "plain"` (also in URL strings) — high',
        '`responseType` / `response_type` containing `token` without `code` (implicit flow) — high',
        '`disableIdTokenValidation: true` — high; `skipIssuerCheck: true`, `requireHttps: false` — medium',
        '`disableAtHashCheck`, `strictDiscoveryDocumentValidation: false`, `skipSubjectCheck`, `disableIatOffsetValidation` — low',
        'angular-oauth2-oidc `AuthConfig` without a `responseType` (the library defaults to the implicit flow) — medium confidence',
      ],
      limitations: [
        'Configuration loaded at runtime (from JSON files fetched over HTTP, environment variables injected at deploy time) is not visible.',
        'Values built dynamically (`requireHttps: environment.production`) are not evaluated.',
        'Identity-provider settings (allowed flows, redirect URI allowlists) are outside the repository and not assessed.',
      ],
      falsePositives: [
        '`requireHttps: false` in a configuration used only for local development is reported; keep such configs in development-only environment files and exclude them, or use `requireHttps: "remoteOnly"`.',
      ],
      remediation:
        "Use the authorization code flow with PKCE (S256): `responseType: 'code'`, leave `disablePKCE`, `skipIssuerCheck`, `disableIdTokenValidation` and friends at their defaults, and keep `requireHttps: true` (or `'remoteOnly'`).",
      example: {
        unsafe: `export const authConfig: AuthConfig = {
  issuer: 'https://login.example.com',
  clientId: 'spa',
  responseType: 'id_token token',
  disablePKCE: true,
  requireHttps: false,
};`,
        safe: `export const authConfig: AuthConfig = {
  issuer: 'https://login.example.com',
  clientId: 'spa',
  responseType: 'code',
  redirectUri: window.location.origin + '/callback',
};`,
      },
      references: [
        { title: 'RFC 9700 — OAuth 2.0 Security Best Current Practice', url: 'https://www.rfc-editor.org/rfc/rfc9700' },
        { title: 'RFC 7636 — PKCE (S256 vs plain)', url: 'https://www.rfc-editor.org/rfc/rfc7636#section-4.2' },
        { title: 'OAuth 2.0 for Browser-Based Apps', url: 'https://datatracker.ietf.org/doc/draft-ietf-oauth-browser-based-apps/' },
      ],
    },
  },
  analyze(ctx) {
    const t = ctx.ts;
    const findings: RuleFinding[] = [];
    for (const sf of codeFiles(ctx)) {
      const visit = (n: ts.Node): void => {
        if (t.isObjectLiteralExpression(n)) {
          const props = n.properties.filter((p): p is ts.PropertyAssignment => t.isPropertyAssignment(p) && (t.isIdentifier(p.name) || t.isStringLiteralLike(p.name)));
          const keys = props.map((p) => (p.name as ts.Identifier).text);
          const oauth2oidc = isOAuth2OidcConfig(ctx, n);
          if (oauth2oidc || keys.some((k) => CONFIG_KEYS.test(k))) {
            for (const p of props) {
              const key = (p.name as ts.Identifier).text;
              const w = WEAKENINGS.find((x) => x.key === key);
              if (!w) continue;
              const v = value(ctx, p.initializer);
              if (!w.matches(v)) continue;
              findings.push({ node: p, message: w.message, confidence: w.confidence, severity: w.severity, evidenceKind: 'pattern', evidence: [`${key}: ${JSON.stringify(v)}`, oauth2oidc ? 'angular-oauth2-oidc AuthConfig' : 'object literal with OAuth client settings'] });
            }
            if (oauth2oidc && !keys.includes('responseType') && keys.includes('issuer')) {
              findings.push({ node: n, message: 'angular-oauth2-oidc AuthConfig without responseType: the library then uses the implicit flow. Set responseType: "code" to use the authorization code flow with PKCE.', confidence: 'medium', severity: 'medium', evidenceKind: 'pattern', evidence: ['AuthConfig from angular-oauth2-oidc', 'responseType not set (library default: implicit flow)'] });
            }
          }
        }
        if ((t.isStringLiteralLike(n) || t.isTemplateHead(n) || t.isTemplateMiddle(n) || t.isTemplateTail(n)) && /code_challenge_method=plain\b/i.test(n.text)) {
          findings.push({ node: n, message: "Authorization request uses the PKCE 'plain' challenge method; use S256.", confidence: 'high', severity: 'high', evidenceKind: 'pattern', evidence: ['code_challenge_method=plain'] });
        }
        t.forEachChild(n, visit);
      };
      visit(sf);
    }
    return findings;
  },
});
