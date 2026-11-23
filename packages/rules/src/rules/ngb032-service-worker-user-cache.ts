import type * as ts from 'typescript';
import { defineRule, type AnalysisContext, type RuleFinding } from '@ngbastion/plugin-api';
import { relative } from '../shared/common.js';
import { readJson, textLocation } from '../shared/files.js';
import { USER_ENDPOINT } from './ngb031-sensitive-cache-storage.js';

const SW_FILE = /(^|[/\\])(sw|service-?worker|custom-sw|[\w-]+-sw|[\w-]+\.sw)\.(js|mjs|ts)$/i;
/** Request properties whose inspection means the handler decides what to cache. */
const DISCRIMINATING = /\b(request|req|r)\s*\.\s*(method|headers|credentials|mode|destination|url)\b|\burl\s*\.\s*(pathname|origin|hostname)\b|\.has\(\s*['"]authorization['"]|\bnew URL\(/i;

interface DataGroup {
  name: string;
  urls: string[];
  strategy?: string;
}

/** Angular service worker `dataGroups` that cache per-user API responses. */
function ngswFindings(ctx: AnalysisContext): RuleFinding[] {
  const out: RuleFinding[] = [];
  for (const file of ctx.findFiles('**/ngsw-config.json')) {
    const parsed = readJson(ctx, file);
    const groups = (parsed?.json as { dataGroups?: { name?: string; urls?: unknown; cacheConfig?: { strategy?: string } }[] } | undefined)?.dataGroups;
    if (!parsed || !Array.isArray(groups)) continue;
    for (const g of groups as DataGroup[] & { cacheConfig?: { strategy?: string } }[]) {
      const urls = Array.isArray(g.urls) ? g.urls.filter((u): u is string => typeof u === 'string') : [];
      const hits = urls.filter((u) => USER_ENDPOINT.test(u.startsWith('/') ? u : `/${u}`) || /^\/?api\/\*\*$/.test(u) || u === '/**' || u === '**');
      if (!hits.length) continue;
      const strategy = (g as { cacheConfig?: { strategy?: string } }).cacheConfig?.strategy ?? 'performance';
      const idx = parsed.text.indexOf(JSON.stringify(hits[0]));
      out.push({
        location: textLocation(file, parsed.text, idx, hits[0]!.length + 2),
        message: `Angular service worker data group '${g.name ?? '?'}' caches user-specific API responses (${hits.join(', ')}) with the '${strategy}' strategy; they persist in CacheStorage after logout and can be served to the next user of the device.`,
        confidence: strategy === 'performance' ? 'high' : 'medium',
        evidenceKind: 'pattern',
        evidence: [`${relative(ctx, file)}: dataGroups[${JSON.stringify(g.name ?? '?')}].urls`, `strategy: ${strategy}${strategy === 'freshness' ? ' (network first; cached copy used offline / on timeout)' : ' (cache first)'}`],
      });
    }
  }
  return out;
}

/** Custom service worker `fetch` handlers that `cache.put()` every request they see. */
function customSwFindings(ctx: AnalysisContext): RuleFinding[] {
  const t = ctx.ts;
  const out: RuleFinding[] = [];
  const files = new Map<string, ts.SourceFile>();
  for (const sf of ctx.sourceFiles) if (SW_FILE.test(sf.fileName)) files.set(sf.fileName, sf);
  for (const f of ctx.findFiles('**/*.{js,mjs}')) {
    if (!SW_FILE.test(f) || /(^|\/)(dist|node_modules|\.angular)\//.test(relative(ctx, f)) || /ngsw-worker|safety-worker/.test(f) || files.has(f)) continue;
    const text = ctx.readFile(f);
    if (text) files.set(f, t.createSourceFile(f, text, t.ScriptTarget.Latest, true, t.ScriptKind.JS));
  }
  for (const sf of files.values()) {
    const visit = (n: ts.Node): void => {
      // self.addEventListener('fetch', handler)  /  self.onfetch = handler
      let handler: ts.Node | undefined;
      if (t.isCallExpression(n) && t.isPropertyAccessExpression(n.expression) && n.expression.name.text === 'addEventListener'
        && n.arguments[0] && t.isStringLiteralLike(n.arguments[0]) && n.arguments[0].text === 'fetch') handler = n.arguments[1];
      if (t.isBinaryExpression(n) && t.isPropertyAccessExpression(n.left) && n.left.name.text === 'onfetch') handler = n.right;
      if (handler && (t.isArrowFunction(handler) || t.isFunctionExpression(handler))) {
        const body = handler.body.getText();
        let put: ts.Node | undefined;
        const findPut = (x: ts.Node): void => {
          if (!put && t.isCallExpression(x) && t.isPropertyAccessExpression(x.expression) && x.expression.name.text === 'put' && x.arguments.length === 2) put = x;
          t.forEachChild(x, findPut);
        };
        findPut(handler.body);
        if (put && !DISCRIMINATING.test(body)) {
          out.push({
            node: put,
            message: 'Service worker fetch handler stores every response it sees in CacheStorage without checking the request (method, URL, credentials or Authorization header); authenticated API responses are cached and outlive the session.',
            confidence: 'medium',
            evidenceKind: 'pattern',
            evidence: [`fetch handler in ${relative(ctx, sf.fileName)}`, 'cache.put(request, response) with no request filtering in the handler'],
          });
        }
      }
      t.forEachChild(n, visit);
    };
    visit(sf);
  }
  return out;
}

export const ngb032 = defineRule({
  meta: {
    id: 'NGB032',
    name: 'Service worker caches user-specific responses',
    category: 'sensitive-data',
    defaultSeverity: 'medium',
    cwe: ['CWE-524', 'CWE-525'],
    docs: {
      description:
        "Reports service-worker caching of authenticated or per-user API responses: Angular service worker `ngsw-config.json` `dataGroups` whose URL patterns cover user, account, session, order or payment endpoints (or the whole API), and custom service workers (`sw.js`, `service-worker.ts`, `*-sw.js`) whose `fetch` handler calls `cache.put()` without inspecting the request.",
      rationale:
        "Service-worker caches live in CacheStorage: they persist across logout and browser restarts, are shared by everyone using the browser profile, and are served before the network. A data group with the `performance` strategy (cache first) can show the previous user's account page to the next person on a shared device, and a cache-everything worker stores tokens and personal data on disk.",
      patterns: [
        '`ngsw-config.json`: `dataGroups[].urls` matching `/api/me`, `/users`, `/account`, `/session`, `/auth`, `/token`, `/orders`, `/payments`, `/billing`, `/cart`, `/messages` … or catch-alls such as `/api/**` (high confidence with `performance`, medium with `freshness`)',
        "Custom workers: `self.addEventListener('fetch', …)` / `self.onfetch = …` that call `cache.put(request, response)` and never look at `request.method`, `request.url`, `request.headers`, `request.credentials`, `request.mode` or `request.destination` (JavaScript files are parsed syntactically)",
        'The generated `ngsw-worker.js` and build output folders are ignored',
      ],
      limitations: [
        'Workbox configurations (`workbox-config.js`, `registerRoute(...)` strategies) are not analyzed.',
        'Custom workers are matched by file name; workers with other names are not found.',
        'Whether the application clears caches on logout is not verified.',
      ],
      falsePositives: [
        'Data groups for endpoints that look user-specific but return public data (e.g. `/api/orders/statuses`) can be reported.',
      ],
      remediation:
        "Only cache public, non-personal API responses in `dataGroups`, or use the `freshness` strategy with a short `maxAge` and clear caches on logout. In custom workers, skip non-GET requests, requests with credentials or an `Authorization` header, and personal endpoints before calling `cache.put()`.",
      example: {
        unsafe: `"dataGroups": [{ "name": "api", "urls": ["/api/**"], "cacheConfig": { "strategy": "performance", "maxAge": "7d", "maxSize": 100 } }]`,
        safe: `"dataGroups": [{ "name": "catalog", "urls": ["/api/catalog/**"], "cacheConfig": { "strategy": "freshness", "maxAge": "1h", "maxSize": 50 } }]`,
      },
      references: [
        { title: 'Angular — Service worker configuration (dataGroups)', url: 'https://angular.dev/ecosystem/service-workers/config' },
        { title: 'MDN — Service Worker API / CacheStorage', url: 'https://developer.mozilla.org/docs/Web/API/CacheStorage' },
      ],
    },
  },
  analyze(ctx) {
    return [...ngswFindings(ctx), ...customSwFindings(ctx)];
  },
});
