import type * as ts from 'typescript';
import { defineRule, type AnalysisContext, type RuleFinding, type SourceLocation } from '@ngbastion/plugin-api';
import { memberName, receiverOf, relative, strip } from '../shared/common.js';
import { objectProp } from '../shared/http.js';
import { readJson, textLocation } from '../shared/files.js';
import { flowFinding, taintedFlow } from '../shared/server-flow.js';

const HEADER = 'service-worker-allowed';

interface HeaderRule {
  /** Path pattern the header is served for (`**` for global headers). */
  source: string;
  value: string;
  location: SourceLocation;
  origin: string;
}

/** Only a literal script file (`/sw.js`, `/assets/ngsw-worker.js`) limits which scripts receive the header. */
const narrow = (source: string) => /(^|\/)[^/*?()[\]{}]+\.m?js$/i.test(source.trim());

/** `Service-Worker-Allowed` together with the path pattern it applies to, from hosting configs and `_headers`. */
function headerRules(ctx: AnalysisContext): HeaderRule[] {
  const out: HeaderRule[] = [];
  for (const file of ['firebase.json', 'vercel.json', 'staticwebapp.config.json'].flatMap((g) => ctx.findFiles(g))) {
    const parsed = readJson(ctx, file);
    if (!parsed) continue;
    const add = (source: string, value: string) => {
      const idx = parsed.text.indexOf(JSON.stringify(value), Math.max(0, parsed.text.search(/service-worker-allowed/i)));
      out.push({ source, value, location: textLocation(file, parsed.text, idx, value.length + 2), origin: relative(ctx, file) });
    };
    const walk = (v: unknown): void => {
      if (Array.isArray(v)) return v.forEach(walk);
      if (!v || typeof v !== 'object') return;
      const o = v as Record<string, unknown>;
      const source = [o.source, o.glob, o.regex, o.route].find((s): s is string => typeof s === 'string');
      if (source !== undefined && o.headers) {
        const hs = o.headers;
        if (Array.isArray(hs)) for (const h of hs as { key?: unknown; value?: unknown }[]) {
          if (typeof h?.key === 'string' && h.key.toLowerCase() === HEADER && typeof h.value === 'string') add(source, h.value);
        } else if (typeof hs === 'object') for (const [k, x] of Object.entries(hs as Record<string, unknown>)) if (k.toLowerCase() === HEADER && typeof x === 'string') add(source, x);
      }
      // Azure Static Web Apps: headers for every response.
      if (o.globalHeaders && typeof o.globalHeaders === 'object') {
        for (const [k, x] of Object.entries(o.globalHeaders as Record<string, unknown>)) if (k.toLowerCase() === HEADER && typeof x === 'string') add('**', x);
      }
      for (const [k, x] of Object.entries(o)) if (!(source !== undefined && k === 'headers') && k !== 'globalHeaders') walk(x);
    };
    walk(parsed.json);
  }
  for (const file of ctx.findFiles('**/_headers')) {
    const text = ctx.readFile(file);
    if (!text) continue;
    let path = '';
    let offset = 0;
    for (const line of text.split(/\n/)) {
      if (/^\S/.test(line) && !line.startsWith('#')) path = line.trim();
      const m = /^\s+service-worker-allowed:\s*(.+?)\s*$/i.exec(line);
      if (m && path) out.push({ source: path, value: m[1]!, location: textLocation(file, text, offset, line.length), origin: relative(ctx, file) });
      offset += line.length + 1;
    }
  }
  return out;
}

/** Server code: `res.setHeader('Service-Worker-Allowed', v)` outside a route for a specific script. */
function serverHeaders(ctx: AnalysisContext): { call: ts.CallExpression; value: string }[] {
  const t = ctx.ts;
  const out: { call: ts.CallExpression; value: string }[] = [];
  for (const call of ctx.index.calls) {
    const [k, v] = call.arguments;
    if (!k || !v || !['setHeader', 'set', 'header', 'append'].includes(memberName(ctx, strip(ctx, call.expression)) ?? '')) continue;
    if (ctx.symbols.constantString(k)?.toLowerCase() !== HEADER) continue;
    const value = ctx.symbols.constantString(v);
    if (value === undefined || ctx.flow.guards(call).length) continue;
    // app.get('/sw.js', (req, res) => res.setHeader(…)) only serves it for that script.
    let scoped = false;
    for (let p: ts.Node | undefined = call.parent; p && !scoped; p = p.parent) {
      if (t.isCallExpression(p) && p.arguments[0] && narrow(ctx.symbols.constantString(p.arguments[0]) ?? '')) scoped = true;
    }
    if (!scoped) out.push({ call, value });
  }
  return out;
}

export const ngb071 = defineRule({
  meta: {
    id: 'NGB071',
    name: 'Service worker scope expansion',
    category: 'security-config',
    defaultSeverity: 'medium',
    cwe: ['CWE-668', 'CWE-284'],
    docs: {
      description:
        "Reports `Service-Worker-Allowed` response headers that are sent for more than the service-worker script itself — for path globs or all responses in `firebase.json`, `vercel.json`, `staticwebapp.config.json` (`globalHeaders` / routes) and `_headers` files, or set by server middleware outside a route for a specific `.js` file — and `navigator.serviceWorker.register(url, { scope })` calls whose scope comes from untrusted data.",
      rationale:
        "A service worker may only control pages below its script's directory unless the script response carries `Service-Worker-Allowed`. When that header is attached to every response (or every `*.js` file), any script an attacker can get served from your origin — an uploaded file, a JSONP endpoint, a user-controlled path on a CDN folder — can be registered as a worker for the whole site and then intercept every request, persistently.",
      patterns: [
        "Hosting configs: `{ \"source\": \"**\", \"headers\": [{ \"key\": \"Service-Worker-Allowed\", \"value\": \"/\" }] }` and any source that is not a literal script file (medium for `/`, low for narrower scopes)",
        '`_headers` blocks for wildcard paths containing `Service-Worker-Allowed`',
        "Server code: `res.setHeader('Service-Worker-Allowed', '/')` without a condition and outside `app.get('/sw.js', …)`",
        "`navigator.serviceWorker.register(url, { scope })` with a traced untrusted `scope`",
      ],
      limitations: [
        'Reverse-proxy configurations (nginx, Apache, CDN rules) are not read.',
        'Whether the origin actually serves attacker-influenced JavaScript is not assessed; the finding reports the widened precondition.',
      ],
      falsePositives: [
        'A wildcard source that in practice only matches the worker script (e.g. a folder that only contains `sw.js`) is reported; narrow the source to the script path.',
      ],
      remediation:
        'Serve the service worker from the scope it controls (usually the site root) so the header is not needed. If it must live in a sub-folder, send `Service-Worker-Allowed` only for that one script path (`"source": "/assets/sw.js"`), never for globs or all responses.',
      example: {
        unsafe: `{ "source": "**", "headers": [{ "key": "Service-Worker-Allowed", "value": "/" }] }`,
        safe: `{ "source": "/assets/sw.js", "headers": [{ "key": "Service-Worker-Allowed", "value": "/" }] }`,
      },
      references: [
        { title: 'W3C Service Workers — Service-Worker-Allowed', url: 'https://w3c.github.io/ServiceWorker/#service-worker-allowed' },
        { title: 'MDN — ServiceWorkerContainer.register() scope', url: 'https://developer.mozilla.org/docs/Web/API/ServiceWorkerContainer/register' },
      ],
    },
  },
  analyze(ctx) {
    const findings: RuleFinding[] = [];
    for (const h of headerRules(ctx)) {
      if (narrow(h.source)) continue;
      const root = h.value.trim() === '/';
      findings.push({
        location: h.location,
        message: `${h.origin} sends Service-Worker-Allowed: ${h.value} for '${h.source}', not just the worker script; any script served from those paths can be registered as a service worker controlling ${root ? 'the whole origin' : h.value}.`,
        confidence: 'high',
        severity: root ? 'medium' : 'low',
        evidenceKind: 'pattern',
        evidence: [`source: ${h.source}`, `Service-Worker-Allowed: ${h.value}`],
      });
    }
    for (const { call, value } of serverHeaders(ctx)) {
      findings.push({
        node: call,
        message: `Server sends Service-Worker-Allowed: ${value} unconditionally; any script served by this handler can register a service worker for ${value === '/' ? 'the whole origin' : value}.`,
        confidence: 'medium',
        severity: value.trim() === '/' ? 'medium' : 'low',
        evidenceKind: 'pattern',
        evidence: [`Service-Worker-Allowed: ${value}`, 'no condition or script-specific route around the header'],
      });
    }
    for (const call of ctx.index.calls) {
      const callee = strip(ctx, call.expression);
      if (memberName(ctx, callee) !== 'register' || memberName(ctx, receiverOf(ctx, callee) ?? callee) !== 'serviceWorker' && ctx.symbols.typeOrigin(receiverOf(ctx, callee) ?? callee)?.name !== 'ServiceWorkerContainer') continue;
      const scope = objectProp(ctx, call.arguments[1], 'scope');
      const tv = scope && taintedFlow(ctx, scope, { context: 'url', kinds: ['url', 'message', 'window-name', 'referrer'] });
      if (tv) findings.push(flowFinding(ctx, call, tv, 'service worker scope', `Untrusted data (${tv.flow.source.description}) chooses the scope of a service worker registration.`, { severity: 'medium' }));
    }
    return findings;
  },
});
