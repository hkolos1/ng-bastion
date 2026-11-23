import type * as ts from 'typescript';
import { defineRule, type AnalysisContext, type RuleFinding } from '@ngbastion/plugin-api';
import { relative } from '../shared/common.js';
import { callsNamed, serviceWorkerFiles } from '../shared/server-flow.js';

/** Response checks that keep error pages and opaque responses out of the cache. */
const RESPONSE_CHECK = /\.(ok|status|type)\b|['"]opaque['"]|\bcacheableResponse\b|\bisCacheable\w*\(|\bisValid\w*\(/i;

/** Outermost function around `node` (the event handler or worker-level helper). */
function outermostFunction(ctx: AnalysisContext, node: ts.Node): ts.Node | undefined {
  let found: ts.Node | undefined;
  for (let p: ts.Node | undefined = node.parent; p; p = p.parent) if (ctx.ts.isFunctionLike(p)) found = p;
  return found;
}

export const ngb074 = defineRule({
  meta: {
    id: 'NGB074',
    name: 'Service worker caches unvalidated responses',
    category: 'security-config',
    defaultSeverity: 'medium',
    cwe: ['CWE-349', 'CWE-524'],
    docs: {
      description:
        "Reports `cache.put(request, response)` in custom service workers (`sw.js`, `service-worker.ts`, `*-sw.js`) when the surrounding handler never checks the response (`response.ok`, `response.status`, `response.type` / `'opaque'`). `cache.add()` / `addAll()` reject failed responses and are not reported.",
      rationale:
        "A runtime cache serves its entries instead of the network. Without a response check, whatever came back once — a 500 page, a captive-portal or proxy-injected page, an attacker-influenced error response, or an opaque cross-origin response the worker cannot even inspect — is stored and replayed on every later visit, offline-first, until the cache is cleared. A single bad response poisons the application for that user.",
      patterns: [
        "`cache.put(req, res)` / `cache.put(req, res.clone())` in a service-worker file whose enclosing handler contains no `.ok`, `.status` or `.type` check and no `'opaque'` comparison",
        'Responses the worker creates itself (`new Response(…)`) are not reported',
        'JavaScript workers are parsed syntactically; the generated `ngsw-worker.js` (which validates responses) and build output are ignored',
      ],
      limitations: [
        'Checks in helper functions outside the handler are not followed; any `.ok` / `.status` / `.type` mention counts as a check.',
        'Workbox strategies and plugins (`CacheableResponsePlugin`) are not analyzed.',
        'Workers are found by file name only.',
      ],
      falsePositives: [
        'Caches whose entries are short-lived or always revalidated still store the bad response for that period; the finding is about the missing check.',
      ],
      remediation:
        "Only cache successful, non-opaque responses: `if (response.ok && response.type === 'basic') cache.put(request, response.clone());`. With Workbox use `CacheableResponsePlugin({ statuses: [200] })`. Keep cache-first strategies for versioned static assets.",
      example: {
        unsafe: "const res = await fetch(event.request);\ncache.put(event.request, res.clone());",
        safe: "const res = await fetch(event.request);\nif (res.ok && res.type === 'basic') cache.put(event.request, res.clone());",
      },
      references: [
        { title: 'MDN — Cache.put()', url: 'https://developer.mozilla.org/docs/Web/API/Cache/put' },
        { title: 'Chrome for Developers — Workbox: caching opaque responses', url: 'https://developer.chrome.com/docs/workbox/caching-resources-during-runtime#opaque_responses' },
      ],
    },
  },
  analyze(ctx) {
    const t = ctx.ts;
    const findings: RuleFinding[] = [];
    for (const sf of serviceWorkerFiles(ctx)) {
      for (const put of callsNamed(ctx, sf, ['put'])) {
        if (!t.isPropertyAccessExpression(put.expression) || put.arguments.length !== 2) continue;
        // Cache.put(request, response), not IndexedDB store.put(value, key).
        if (!/cache/i.test(put.expression.expression.getText()) && !/\b(request|req)\b|\.url\b/.test(put.arguments[0]!.getText())) continue;
        const response = put.arguments[1]!;
        if (t.isNewExpression(response) || /^new Response\b/.test(response.getText())) continue;
        const scope = outermostFunction(ctx, put);
        if (!scope || RESPONSE_CHECK.test(scope.getText())) continue;
        findings.push({
          node: put,
          message: 'Service worker stores responses in CacheStorage without checking response.ok / status / type; error pages and opaque cross-origin responses are cached and served on later visits (cache poisoning).',
          confidence: 'medium',
          evidenceKind: 'pattern',
          evidence: [`cache.put() in ${relative(ctx, sf.fileName)}`, 'no .ok / .status / .type check in the enclosing handler'],
        });
      }
    }
    return findings;
  },
});
