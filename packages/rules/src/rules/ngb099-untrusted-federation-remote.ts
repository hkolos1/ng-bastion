import type * as ts from 'typescript';
import { defineRule, type RuleFinding } from '@ngbastion/plugin-api';
import { relative, reportSink, strip } from '../shared/common.js';
import { readJson, textLocation } from '../shared/files.js';
import { isPlaintextRemote, objectLiteral, objectProp } from '../shared/http.js';
import { moduleCall } from '../shared/server.js';
import { configFiles } from '../shared/workflows.js';

const MODULES = [
  '@angular-architects/native-federation', '@angular-architects/module-federation', '@angular-architects/module-federation-runtime',
  '@softarc/native-federation', '@softarc/native-federation-runtime', '@softarc/native-federation-orchestrator',
  '@module-federation/enhanced/runtime', '@module-federation/runtime', '@module-federation/enhanced',
];
const FUNCTIONS = ['loadRemoteModule', 'loadRemoteEntry', 'initFederation', 'init', 'registerRemotes', 'createInstance'];

/** Expressions that decide where remote code is loaded from. */
function remoteUrls(ctx: Parameters<typeof reportSink>[0]['ctx'], fn: string, args: readonly ts.Expression[]): ts.Expression[] {
  const t = ctx.ts;
  const [a0] = args;
  if (!a0) return [];
  const a = strip(ctx, a0);
  const entryOf = (o: ts.Expression) => objectProp(ctx, o, 'remoteEntry') ?? objectProp(ctx, o, 'entry');
  if (fn === 'loadRemoteModule' || fn === 'loadRemoteEntry') {
    if (fn === 'loadRemoteEntry' && !t.isObjectLiteralExpression(a)) return [a0];
    const e = entryOf(a0);
    return e ? [e] : [];
  }
  if (fn === 'initFederation') {
    const o = objectLiteral(ctx, a0);
    if (!o) return t.isArrayLiteralExpression(a) ? [] : [a0]; // manifest URL (string)
    return o.properties.flatMap((p) => (t.isPropertyAssignment(p) ? [p.initializer] : []));
  }
  // init({ remotes: [{ name, entry }] }), registerRemotes([{ name, entry }])
  const list = fn === 'registerRemotes' ? a : objectProp(ctx, a0, 'remotes');
  const arr = list && strip(ctx, list);
  if (!arr || !t.isArrayLiteralExpression(arr)) return [];
  return arr.elements.flatMap((el) => {
    const e = entryOf(el);
    return e ? [e] : [];
  });
}

export const ngb099 = defineRule({
  meta: {
    id: 'NGB099',
    name: 'Untrusted module federation remote',
    category: 'supply-chain',
    defaultSeverity: 'high',
    cwe: ['CWE-829', 'CWE-494'],
    docs: {
      description:
        'Reports micro-frontend remotes whose code location is attacker-controlled or plaintext: remote entry / manifest URLs passed to Native Federation and Module Federation runtime APIs (`loadRemoteModule({ remoteEntry })`, `loadRemoteEntry()`, `initFederation()`, `init({ remotes })`, `registerRemotes()`) that are traced to an untrusted source (URL, storage, postMessage, HTTP response), constant `http://` remote URLs, and `http://` entries in `federation.manifest.json` files.',
      rationale:
        'A federation remote is executable JavaScript loaded into the host application\'s origin; whoever chooses its URL runs code with the user\'s session. Apps that let a query parameter or `localStorage` override remote URLs ("for testing") give that power to any link an attacker can send, and remotes over plain HTTP can be replaced by anyone on the network path.',
      patterns: [
        'Runtime APIs imported from `@angular-architects/native-federation`, `@angular-architects/module-federation`, `@softarc/native-federation*` or `@module-federation/(enhanced/)runtime`',
        'Remote URL arguments with a traced untrusted source (data flow, resource-URL context)',
        'Constant `http://` remote URLs and manifest entries (loopback / private hosts excluded)',
      ],
      limitations: [
        'Webpack `ModuleFederationPlugin` `remotes` in build configuration and remotes loaded from a manifest fetched at runtime are not traced; only the manifest URL is.',
        'Manifest JSON content served by a backend is not visible.',
      ],
      falsePositives: [
        'Remote URLs from a backend endpoint you control are reported when the HTTP response is the only source (medium confidence); validate them against an allowlist to document the trust decision.',
      ],
      remediation:
        'Load remotes only from a fixed list of HTTPS origins built into the host (or a signed / same-origin manifest). If remote overrides are needed for testing, restrict them to development builds and validate each URL against an origin allowlist.',
      example: {
        unsafe: `loadRemoteModule({ remoteEntry: route.snapshot.queryParams['remote'], exposedModule: './Routes' })`,
        safe: `loadRemoteModule({ remoteEntry: 'https://mfe.example.com/remoteEntry.json', exposedModule: './Routes' })`,
      },
      references: [
        { title: 'Native Federation for Angular', url: 'https://www.npmjs.com/package/@angular-architects/native-federation' },
        { title: 'Module Federation — runtime API', url: 'https://module-federation.io/guide/runtime/runtime-api.html' },
      ],
    },
  },
  analyze(ctx) {
    const findings: RuleFinding[] = [];
    for (const call of ctx.index.calls) {
      const fn = moduleCall(ctx, call, MODULES, FUNCTIONS);
      if (!fn) continue;
      for (const url of remoteUrls(ctx, fn, call.arguments)) {
        const constant = ctx.symbols.constantString(url);
        if (constant !== undefined) {
          if (isPlaintextRemote(constant, 'http')) {
            findings.push({ node: url, message: `${fn}() loads remote code over plain HTTP (${constant}); anyone on the network path can replace it.`, confidence: 'high', evidenceKind: 'pattern', evidence: [`remote: ${constant}`] });
          }
          continue;
        }
        findings.push(...reportSink({
          ctx, sink: url, value: url, context: 'resource-url', sinkDescription: `${fn}() remote URL`,
          message: (f) => `The ${fn}() remote URL comes from ${f.source.description}; an attacker can make the app load and run their own remote code.`,
        }));
      }
    }
    for (const file of configFiles(ctx, '**/federation.manifest.json')) {
      const parsed = readJson(ctx, file);
      if (!parsed || !parsed.json || typeof parsed.json !== 'object') continue;
      for (const [name, url] of Object.entries(parsed.json as Record<string, unknown>)) {
        if (typeof url !== 'string' || !isPlaintextRemote(url, 'http')) continue;
        findings.push({ location: textLocation(file, parsed.text, parsed.text.indexOf(JSON.stringify(url)), url.length + 2), message: `Federation remote '${name}' is loaded over plain HTTP (${url}); anyone on the network path can replace its code.`, confidence: 'high', evidenceKind: 'pattern', evidence: [`${relative(ctx, file)}: ${name} → ${url}`] });
      }
    }
    return findings;
  },
});
