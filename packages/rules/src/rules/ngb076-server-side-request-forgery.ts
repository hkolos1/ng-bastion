import type * as ts from 'typescript';
import { defineRule, type AnalysisContext, type RuleFinding } from '@ngbastion/plugin-api';
import { hasFixedOrigin } from '../shared/common.js';
import { objectLiteral, objectProp, urlParts } from '../shared/http.js';
import { moduleCall, nodeModules } from '../shared/server.js';
import { urlValidation, valueNames } from '../shared/url-guards.js';
import { flowFinding, REQUEST_KINDS, SERVER_SOURCE, taintedFlow, type TaintedValue } from '../shared/server-flow.js';

const VERBS = ['get', 'post', 'put', 'patch', 'delete', 'head', 'options', 'request'];
/** Node HTTP clients: [modules, functions, kind of first argument]. Global `fetch()` is NGB026. */
const CLIENTS: [modules: string[], fns: string[], label: string][] = [
  [nodeModules('http', 'https'), ['get', 'request'], 'http'],
  [['axios'], ['axios', 'default', ...VERBS, 'getUri'], 'axios'],
  [['got'], ['got', 'default', ...VERBS, 'stream', 'paginate'], 'got'],
  [['node-fetch', 'cross-fetch', 'isomorphic-fetch'], ['fetch', 'default'], 'node-fetch'],
  [['undici'], ['fetch', 'request', 'stream'], 'undici'],
  [['superagent'], [...VERBS, 'del', 'default'], 'superagent'],
  [['needle'], [...VERBS, 'needle', 'default'], 'needle'],
];

/** URL or the `url` / `baseURL` / `host` / `hostname` of an options object. */
function destination(ctx: AnalysisContext, arg: ts.Expression): ts.Expression[] {
  const o = objectLiteral(ctx, arg);
  if (!o) return [arg];
  return ['url', 'baseURL', 'host', 'hostname', 'origin', 'prefixUrl'].map((k) => objectProp(ctx, o, k)).filter((x): x is ts.Expression => !!x);
}

/** First request-controlled part of the URL, and whether a fixed `https://host/` precedes it. */
function taintedPart(ctx: AnalysisContext, url: ts.Expression): { tv: TaintedValue; position: 'origin' | 'path'; expr: ts.Expression } | undefined {
  let prefix = '';
  for (const p of urlParts(ctx, url)) {
    if (p.text !== undefined) {
      prefix += p.text;
      continue;
    }
    if (/[?#]/.test(prefix)) return undefined; // query / fragment values do not choose the destination
    const tv = taintedFlow(ctx, p.expr, { context: 'url', kinds: REQUEST_KINDS, skip: (f) => !SERVER_SOURCE.test(f.source.description) });
    if (tv) return { tv, position: hasFixedOrigin(prefix) || /^\/[^/\\]/.test(prefix) ? 'path' : 'origin', expr: p.expr };
    prefix += '';
  }
  return undefined;
}

export const ngb076 = defineRule({
  meta: {
    id: 'NGB076',
    name: 'Server-side request forgery',
    category: 'ssr',
    defaultSeverity: 'high',
    cwe: ['CWE-918'],
    docs: {
      description:
        "Traces request data (Express / Node query, params, body, cookies, headers) into the destination of outgoing requests made with Node.js HTTP clients in server code: `http.get/request`, `https.get/request`, axios, got, node-fetch, undici, superagent, and needle. Browser APIs and the global `fetch()` are covered by NGB026, the `Host` header by NGB042.",
      rationale:
        'SSR servers and BFFs run inside the network perimeter: they can reach cloud metadata endpoints (`169.254.169.254`), internal admin APIs and databases. If a client chooses the host of a server-side request it can read those services through your server (SSRF); with only the path chosen it can still call internal endpoints you never meant to expose.',
      patterns: [
        "`axios.get(req.query.url)`, `got(`${req.body.webhook}`)`, `https.get({ host: req.query.host })`, `fetch(url)` imported from `node-fetch` / `undici` …",
        'Origin control (the request value is first or follows only a scheme) — high; path control after a fixed `https://host/` or `/` — medium',
        'Recognized validation: host allowlists and same-origin checks dominating the call (as NGB011 / NGB026), `encodeURIComponent()` on path segments, numeric conversion',
      ],
      limitations: [
        'Client instances (`axios.create({ baseURL })` then `api.get(path)`) are not followed; only module-level calls are matched.',
        'DNS rebinding and redirects to internal hosts after an allowlisted host are not assessed.',
      ],
      falsePositives: [
        'Destinations validated by a project function (`if (isAllowed(url))`) are reported with lowered confidence; register the check as an inline allowlist comparison or document an exception.',
      ],
      remediation:
        'Do not let clients choose request destinations. Map an identifier to a configured URL, or parse the value with `new URL()` and compare `hostname` against an allowlist (and block private address ranges after DNS resolution). Encode path segments with `encodeURIComponent()`.',
      example: {
        unsafe: 'const preview = await axios.get(req.query.url as string);',
        safe: "const target = new URL(String(req.query.url));\nif (!ALLOWED_HOSTS.has(target.hostname)) return res.sendStatus(400);\nconst preview = await axios.get(target.toString());",
      },
      references: [
        { title: 'OWASP — Server-Side Request Forgery Prevention Cheat Sheet', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html' },
        { title: 'PortSwigger — Server-side request forgery', url: 'https://portswigger.net/web-security/ssrf' },
      ],
    },
  },
  analyze(ctx) {
    const findings: RuleFinding[] = [];
    for (const call of ctx.index.calls) {
      const arg = call.arguments[0];
      if (!arg) continue;
      let label: string | undefined;
      for (const [modules, fns, l] of CLIENTS) {
        const fn = moduleCall(ctx, call, modules, fns);
        if (fn) {
          label = fn === l || fn === 'default' ? `${l}()` : `${l}.${fn}()`;
          break;
        }
      }
      if (!label) continue;
      for (const url of destination(ctx, arg)) {
        const hit = taintedPart(ctx, url);
        if (!hit) continue;
        const v = urlValidation(ctx, call, valueNames(ctx, hit.expr, hit.tv.result.names));
        if (v.host === 'strong') break;
        const f = flowFinding(ctx, call, hit.tv, `${label} destination`,
          hit.position === 'origin'
            ? `Request data (${hit.tv.flow.source.description}) chooses the host of a server-side ${label} request; clients can make the server call internal services or cloud metadata endpoints (SSRF).`
            : `Request data (${hit.tv.flow.source.description}) chooses the path of a server-side ${label} request to a fixed host; clients can reach other endpoints of that service.`,
          { severity: hit.position === 'origin' ? 'high' : 'medium', evidence: v.evidence.length ? [`validation seen: ${v.evidence.join('; ')}`] : [] });
        if (v.host) f.confidence = 'low';
        findings.push(f);
        break;
      }
    }
    return findings;
  },
});
