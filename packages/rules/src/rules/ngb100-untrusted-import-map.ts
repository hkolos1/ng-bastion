import type * as ts from 'typescript';
import { defineRule, type RuleFinding } from '@ngbastion/plugin-api';
import { memberName, receiverOf, relative, reportSink, strip } from '../shared/common.js';
import { textLocation } from '../shared/files.js';
import { isPlaintextRemote } from '../shared/http.js';

const IMPORTMAP = /<script\b[^>]*\btype\s*=\s*["']?importmap["']?[^>]*>([\s\S]*?)<\/script>/gi;
const TEXT_PROPS = new Set(['textContent', 'text', 'innerHTML', 'innerText']);

/** Every string value of `imports` / `scopes` (nested one level). */
function mapUrls(json: unknown): string[] {
  if (!json || typeof json !== 'object') return [];
  const o = json as { imports?: unknown; scopes?: unknown };
  const vals = (x: unknown) => (x && typeof x === 'object' ? Object.values(x as Record<string, unknown>) : []);
  return [...vals(o.imports), ...vals(o.scopes).flatMap(vals)].filter((v): v is string => typeof v === 'string');
}

export const ngb100 = defineRule({
  meta: {
    id: 'NGB100',
    name: 'Untrusted import map',
    category: 'supply-chain',
    defaultSeverity: 'high',
    cwe: ['CWE-829', 'CWE-494'],
    docs: {
      description:
        'Reports import maps that let someone else decide which code a bare module specifier loads: entries in `<script type="importmap">` of `index.html` that point at plain `http://` URLs, script elements whose `type` is set to `importmap` and whose content is filled from an untrusted source, and `importShim.addImportMap()` (es-module-shims) with untrusted input.',
      rationale:
        'An import map rewrites every `import "x"` of the page. Mapping a package to an HTTP URL lets a network attacker replace it; building the map from a query parameter or storage lets anyone who can send a link remap `@angular/core` or the app\'s own chunks to their script — full script execution in the app\'s origin without any HTML injection.',
      patterns: [
        '`<script type="importmap">{ "imports": { "lib": "http://…" } }</script>` in the configured `index.html` (`imports` and `scopes`; loopback / private hosts excluded)',
        '`el.type = "importmap"` or `el.setAttribute("type", "importmap")` and `el.textContent | text | innerHTML = value` on the same element variable, with `value` traced to an untrusted source',
        '`importShim.addImportMap(value)` with `value` traced to an untrusted source',
      ],
      limitations: [
        'Import maps served by a backend or injected by SSR templates are not visible.',
        'Only element variables within one file are correlated.',
      ],
      falsePositives: [
        'Maps built from a backend response you control are reported (medium confidence); validate the URLs against an origin allowlist before installing the map.',
      ],
      remediation:
        'Keep import maps static and same-origin (or HTTPS with `integrity` metadata). Never build an import map from URL parameters, storage or messages; if overrides are needed for development, compile them out of production builds.',
      example: {
        unsafe: `script.type = 'importmap';
script.textContent = JSON.stringify({ imports: { app: new URLSearchParams(location.search).get('app') } });`,
        safe: `<script type="importmap">{ "imports": { "app": "/assets/app-3f2a1c.js" } }</script>`,
      },
      references: [
        { title: 'MDN — <script type="importmap">', url: 'https://developer.mozilla.org/docs/Web/HTML/Reference/Elements/script/type/importmap' },
        { title: 'es-module-shims — dynamic import maps', url: 'https://github.com/guybedford/es-module-shims#dynamic-import-maps' },
      ],
    },
  },
  analyze(ctx) {
    const t = ctx.ts;
    const findings: RuleFinding[] = [];
    const index = ctx.project.indexHtml;
    const html = index && ctx.readFile(index);
    if (index && html) {
      for (const m of html.replace(/<!--[\s\S]*?-->/g, (c) => ' '.repeat(c.length)).matchAll(IMPORTMAP)) {
        let json: unknown;
        try {
          json = JSON.parse(m[1]!);
        } catch {
          continue;
        }
        for (const url of mapUrls(json).filter((u) => isPlaintextRemote(u, 'http'))) {
          const at = html.indexOf(JSON.stringify(url), m.index);
          findings.push({ location: textLocation(index, html, at < 0 ? m.index! : at, url.length + 2), message: `The import map in ${relative(ctx, index)} resolves a module to ${url} over plain HTTP; a network attacker can replace that code.`, confidence: 'high', evidenceKind: 'pattern', evidence: [`importmap entry: ${url}`] });
        }
      }
    }
    // Element variables whose type becomes "importmap".
    const maps = new Set<ts.Declaration>();
    const declOf = (e: ts.Expression | undefined) => (e && t.isIdentifier(strip(ctx, e)) ? ctx.symbols.declarationOf(strip(ctx, e)) : undefined);
    for (const a of ctx.index.assignments) {
      if (memberName(ctx, a.left) === 'type' && ctx.symbols.constantString(a.right) === 'importmap') {
        const d = declOf(receiverOf(ctx, a.left));
        if (d) maps.add(d);
      }
    }
    for (const c of ctx.index.calls) {
      if (memberName(ctx, c.expression) === 'setAttribute' && c.arguments[0] && ctx.symbols.constantString(c.arguments[0]) === 'type' && c.arguments[1] && ctx.symbols.constantString(c.arguments[1]) === 'importmap') {
        const d = declOf(receiverOf(ctx, c.expression));
        if (d) maps.add(d);
      }
      if (memberName(ctx, c.expression) === 'addImportMap' && /^importShim$/.test(receiverOf(ctx, c.expression)?.getText() ?? '') && c.arguments[0]) {
        findings.push(...reportSink({ ctx, sink: c, value: c.arguments[0], context: 'script', sinkDescription: 'importShim.addImportMap()', message: (f) => `importShim.addImportMap() installs an import map built from ${f.source.description}; an attacker can remap modules to their own code.` }));
      }
    }
    if (maps.size) {
      for (const a of ctx.index.assignments) {
        const prop = memberName(ctx, a.left);
        const d = prop && TEXT_PROPS.has(prop) ? declOf(receiverOf(ctx, a.left)) : undefined;
        if (!d || !maps.has(d)) continue;
        findings.push(...reportSink({ ctx, sink: a, value: a.right, context: 'script', sinkDescription: `import map ${prop} assignment`, message: (f) => `An import map is filled from ${f.source.description}; an attacker can remap modules to their own code.` }));
      }
    }
    return findings;
  },
});
