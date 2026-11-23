import type * as ts from 'typescript';
import { defineRule, type AnalysisContext, type RuleFinding } from '@ngbastion/plugin-api';
import { relative } from '../shared/common.js';
import { fetchHandlers, serviceWorkerFiles } from '../shared/server-flow.js';

const AUTH = /^(authorization|proxy-authorization|x-api-key|x-auth-token|x-access-token|api-key|apikey)$/i;
/** The handler inspects where the request goes before adding credentials. */
const ORIGIN_CHECK = /\.(origin|host|hostname)\b|\.startsWith\(|\bnew URL\(|\bmode\s*[!=]==\s*['"]same-origin|\.test\(\s*\w*\.?(request\.)?url|\bincludes\(\s*\w*\.?(request\.)?url/;

/** Where the handler attaches credentials: an Authorization-like header or `credentials: 'include'`. */
function credentialSite(ctx: AnalysisContext, fn: ts.FunctionLikeDeclaration): { node: ts.Node; what: string } | undefined {
  const t = ctx.ts;
  let hit: { node: ts.Node; what: string } | undefined;
  const visit = (n: ts.Node): void => {
    if (hit) return;
    if (t.isPropertyAssignment(n) && n.name && (t.isIdentifier(n.name) || t.isStringLiteralLike(n.name))) {
      const key = n.name.text;
      if (AUTH.test(key)) hit = { node: n, what: `${key} header` };
      else if (key === 'credentials' && t.isStringLiteralLike(n.initializer) && n.initializer.text === 'include') hit = { node: n, what: "credentials: 'include'" };
    }
    if (t.isCallExpression(n) && t.isPropertyAccessExpression(n.expression) && ['set', 'append'].includes(n.expression.name.text)
      && n.arguments[0] && t.isStringLiteralLike(n.arguments[0]) && AUTH.test(n.arguments[0].text)) hit = { node: n, what: `${n.arguments[0].text} header` };
    t.forEachChild(n, visit);
  };
  if (fn.body) visit(fn.body);
  return hit;
}

export const ngb072 = defineRule({
  meta: {
    id: 'NGB072',
    name: 'Service worker attaches credentials to any origin',
    category: 'sensitive-data',
    defaultSeverity: 'high',
    cwe: ['CWE-522', 'CWE-200'],
    docs: {
      description:
        "Reports custom service-worker `fetch` handlers (`sw.js`, `service-worker.ts`, `*-sw.js`) that add an `Authorization` / API-key header or `credentials: 'include'` to intercepted requests without first checking the request's destination (`new URL(request.url).origin`, `url.startsWith(API)`, `request.mode === 'same-origin'`).",
      rationale:
        "A service worker sees every request the page makes — your API, but also third-party images, fonts, analytics and any URL an attacker can get the page to load (an `<img>` in user content). A handler that injects the bearer token into all of them sends it to every one of those hosts. Angular interceptors are covered by NGB013; this is the same mistake one layer lower, where it also affects requests the application never made itself.",
      patterns: [
        "`self.addEventListener('fetch', e => …)` / `self.onfetch = …` handlers that create headers with `Authorization` / `X-Api-Key` … (`{ Authorization: … }`, `headers.set('Authorization', …)`) or `credentials: 'include'`",
        'Not reported when the handler inspects the destination: `.origin`, `.host`, `.hostname`, `.startsWith(…)`, `new URL(…)`, `request.mode === "same-origin"`, URL regex / `includes` tests',
        'JavaScript workers are parsed syntactically; the generated `ngsw-worker.js` and build output are ignored',
      ],
      limitations: [
        'Only inline handler functions are analyzed; handlers defined elsewhere and passed by name are not followed.',
        'Any destination check is accepted; a check that is present but wrong (substring match) is not detected.',
        'Workers are found by file name only.',
      ],
      falsePositives: [
        'A worker deployed only for an API-only origin, where every request is first-party, is reported; add an explicit origin check to make that guarantee visible.',
      ],
      remediation:
        "Attach credentials only to your own API: `const url = new URL(event.request.url); if (url.origin !== API_ORIGIN) return;` before cloning the request with the token. Prefer HttpOnly cookies with `SameSite` over tokens in a service worker.",
      example: {
        unsafe: "self.addEventListener('fetch', (e) => {\n  e.respondWith(fetch(new Request(e.request, { headers: { Authorization: `Bearer ${token}` } })));\n});",
        safe: "self.addEventListener('fetch', (e) => {\n  if (new URL(e.request.url).origin !== API_ORIGIN) return;\n  e.respondWith(fetch(new Request(e.request, { headers: { Authorization: `Bearer ${token}` } })));\n});",
      },
      references: [
        { title: 'MDN — FetchEvent', url: 'https://developer.mozilla.org/docs/Web/API/FetchEvent' },
        { title: 'OWASP — HTML5 Security Cheat Sheet (Service workers)', url: 'https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html' },
      ],
    },
  },
  analyze(ctx) {
    const findings: RuleFinding[] = [];
    for (const sf of serviceWorkerFiles(ctx)) {
      for (const fn of fetchHandlers(ctx, sf)) {
        const site = credentialSite(ctx, fn);
        if (!site || ORIGIN_CHECK.test(fn.body?.getText() ?? '')) continue;
        findings.push({
          node: site.node,
          message: `Service worker fetch handler adds ${site.what} to intercepted requests without checking their destination; the credentials are sent to every third-party host the page loads from.`,
          confidence: site.what.includes('header') ? 'high' : 'medium',
          evidenceKind: 'pattern',
          evidence: [`fetch handler in ${relative(ctx, sf.fileName)}`, `adds ${site.what}`, 'no origin / URL check in the handler'],
        });
      }
    }
    return findings;
  },
});
