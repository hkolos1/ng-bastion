import type * as ts from 'typescript';
import { defineRule, type AnalysisContext, type RuleFinding, type TaintFlow } from '@ngbastion/plugin-api';
import { constantPrefix, flowEvidence, hasFixedOrigin, memberName, sinkStep, strip } from '../shared/common.js';
import { urlValidation, valueNames } from '../shared/url-guards.js';

const KEYS = new Set(['redirect_uri', 'redirectUri', 'redirectUrl', 'post_logout_redirect_uri', 'postLogoutRedirectUri', 'silentRefreshRedirectUri', 'silent_redirect_uri', 'popup_redirect_uri']);
/** Sources that only describe the application's own current URL: the origin stays fixed. */
const OWN_URL = /^(location\.(href|pathname)|document\.(URL|documentURI|baseURI)|Router\.url|Location\.path\(\)|location \(stringified\))/;

function pinned(ctx: AnalysisContext, value: ts.Expression): boolean {
  const p = constantPrefix(ctx, value);
  return !!p && (hasFixedOrigin(p) || /^\/[^/\\]/.test(p));
}

export const ngb060 = defineRule({
  meta: {
    id: 'NGB060',
    name: 'Untrusted OAuth redirect URI',
    category: 'navigation-auth',
    defaultSeverity: 'high',
    cwe: ['CWE-601', 'CWE-522'],
    docs: {
      description:
        "Traces untrusted data (URL query / fragment, postMessage data, `window.name`, referrer, Web Storage) into the OAuth / OIDC redirect URI of an authorization or logout request: `redirect_uri` / `redirectUri` / `post_logout_redirect_uri` / `silentRefreshRedirectUri` properties (client configuration and request parameters), `params.set('redirect_uri', v)`, and `redirect_uri=` inside request URLs. Values pinned by a constant origin or path prefix, the application's own current URL (`location.href`), and values guarded by a host allowlist are not reported.",
      rationale:
        "The redirect URI is where the identity provider delivers the authorization code or tokens. If a link can choose it (`/login?returnTo=https://evil.example/cb`), the code is sent to the attacker. Identity providers that compare redirect URIs exactly stop this; providers configured with wildcards, prefix matching or many registered URIs (including an open redirect on your own domain) do not.",
      patterns: [
        "Object properties `redirect_uri`, `redirectUri`, `redirectUrl`, `post_logout_redirect_uri`, `postLogoutRedirectUri`, `silentRefreshRedirectUri` with an untrusted value",
        "`params.set|append('redirect_uri', v)` on `URLSearchParams` / `HttpParams`",
        "`` `…/authorize?…&redirect_uri=${v}` `` and `'…redirect_uri=' + v`",
        "Not reported: constant prefixes (`location.origin + '/callback'`, `'/auth/' + x`), `location.href` / `Router.url` (own origin), values checked against a host allowlist or same-origin comparison (as NGB011)",
      ],
      limitations: [
        "The identity provider's redirect URI registration is not visible; exact-match providers make the finding unexploitable (confidence is therefore at most medium).",
        "Return-URL parameters passed through `state` and used after the callback are NGB011 (untrusted redirect), not this rule.",
      ],
      falsePositives: [
        'Applications whose identity provider enforces exact redirect URI matching are protected; keep the finding as a defence-in-depth issue or document an exception naming the IdP setting.',
      ],
      remediation:
        "Use a constant redirect URI (`${location.origin}/auth/callback`) registered exactly at the identity provider. Carry the page to return to in `state` (or session storage) and validate it as a same-origin path after sign-in.",
      example: {
        unsafe: "this.oauth.configure({ ...cfg, redirectUri: this.route.snapshot.queryParams['returnTo'] });",
        safe: "this.oauth.configure({ ...cfg, redirectUri: `${location.origin}/auth/callback` });\nsessionStorage.setItem('returnTo', safeRelativePath(this.route.snapshot.queryParams['returnTo']));",
      },
      references: [
        { title: 'OAuth 2.0 Security Best Current Practice (RFC 9700) — Insufficient redirect URI validation', url: 'https://www.rfc-editor.org/rfc/rfc9700#section-4.1' },
        { title: 'PortSwigger — OAuth: leaking authorization codes via redirect_uri', url: 'https://portswigger.net/web-security/oauth#leaking-authorization-codes-and-access-tokens' },
      ],
    },
  },
  analyze(ctx) {
    const t = ctx.ts;
    const findings: RuleFinding[] = [];
    const seen = new Set<ts.Node>();
    const report = (sink: ts.Node, value: ts.Expression, what: string) => {
      if (seen.has(sink) || pinned(ctx, value)) return;
      seen.add(sink);
      const result = ctx.taint.trace(value, { context: 'generic' });
      const flow: TaintFlow | undefined = result.flows.find((f) => f.source.kind !== 'request-header' && !OWN_URL.test(f.source.description));
      if (!flow) return;
      const v = urlValidation(ctx, sink, valueNames(ctx, value, result.names));
      if (v.host === 'strong') return;
      findings.push({
        node: sink,
        message: `${what} comes from ${flow.source.description}; an attacker can make the identity provider deliver the authorization code or tokens to their own URL.`,
        confidence: v.host ? 'low' : flow.confidence === 'high' ? 'medium' : flow.confidence,
        evidenceKind: 'dataflow',
        trace: [...flow.steps, sinkStep(ctx, sink, what)],
        evidence: [...flowEvidence(flow), "identity provider redirect URI allowlist: not assessed"],
      });
    };
    const visit = (n: ts.Node): void => {
      if (t.isPropertyAssignment(n) && n.name && (t.isIdentifier(n.name) || t.isStringLiteralLike(n.name)) && KEYS.has(n.name.text)) report(n, n.initializer, n.name.text);
      if (t.isShorthandPropertyAssignment(n) && KEYS.has(n.name.text)) report(n, n.name, n.name.text);
      if (t.isBinaryExpression(n) && n.operatorToken.kind === t.SyntaxKind.EqualsToken && KEYS.has(memberName(ctx, n.left) ?? '')) report(n, n.right, memberName(ctx, n.left)!);
      if (t.isCallExpression(n) && ['set', 'append'].includes(memberName(ctx, n.expression) ?? '') && n.arguments.length >= 2 && KEYS.has(ctx.symbols.constantString(n.arguments[0]!) ?? '')) report(n, n.arguments[1]!, 'redirect_uri parameter');
      if (t.isTemplateExpression(n)) {
        let text = n.head.text;
        for (const span of n.templateSpans) {
          if (/[?&](redirect_uri|post_logout_redirect_uri)=$/i.test(text)) report(span.expression, span.expression, 'redirect_uri parameter');
          text += `\0${span.literal.text}`;
        }
      }
      if (t.isBinaryExpression(n) && n.operatorToken.kind === t.SyntaxKind.PlusToken) {
        const left = constantSuffix(ctx, n.left);
        if (left && /[?&](redirect_uri|post_logout_redirect_uri)=$/i.test(left)) report(n.right, n.right, 'redirect_uri parameter');
      }
      t.forEachChild(n, visit);
    };
    for (const sf of ctx.sourceFiles) if (!sf.fileName.endsWith('.json')) visit(sf);
    return findings;
  },
});

/** Trailing constant text of the left side of a concatenation. */
function constantSuffix(ctx: AnalysisContext, e: ts.Expression): string | undefined {
  const t = ctx.ts;
  const x = strip(ctx, e);
  const c = ctx.symbols.constantString(x);
  if (c !== undefined) return c;
  if (t.isTemplateExpression(x)) return x.templateSpans[x.templateSpans.length - 1]!.literal.text;
  if (t.isBinaryExpression(x) && x.operatorToken.kind === t.SyntaxKind.PlusToken) return constantSuffix(ctx, x.right);
  return undefined;
}
