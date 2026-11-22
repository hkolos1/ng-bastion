#!/usr/bin/env node
// Regenerates docs/LIMITATIONS.md: engine section below + per-rule limitations from rule metadata.
// Usage: pnpm build && node scripts/generate-limitations.mjs
import { writeFileSync } from 'node:fs';
import { builtinRules } from '../packages/rules/dist/index.js';

const ENGINE = `# Known limitations

NgBastion reports what its bounded model can establish. This page lists what it cannot. Rule
pages (and \`ngbastion explain <ID>\`) repeat the rule-specific items below.

**No findings does not mean the application is secure.**

## Scope

- Static analysis only: the application is never built, served or executed. Runtime-only facts
  (deployed HTTP headers, CDN rules, server-side authorization, actual cache behaviour, browser
  extensions) are not observable. Where a rule depends on them it says "not assessed".
- Not a replacement for penetration testing, server-side security reviews or dependency (SCA)
  scanning. Vulnerabilities inside third-party packages are out of scope.

## Engine (data flow)

- **Bounded, not complete**: depth, call sites per parameter, file hops, visited nodes, paths per
  sink and total time are limited. Hitting a limit produces \`analysis-incomplete\` /
  \`analysis-timeout\`; other paths may exist.
- **Backward and demand-driven**: only sinks that rules ask about are traced.
- **Context-insensitive fallback**: a parameter without a binding context unions all call sites.
- **Field-insensitive containers**: a field read from an untyped object or interface-typed DTO
  inherits the taint of the whole object; arrays and \`Object.assign\` are element-insensitive.
- **Not followed**: values stored in Maps/Sets, closures captured by unrelated callbacks,
  state-management libraries (NgRx, NGXS, Akita, signal stores), \`Reflect\`/proxies, \`eval\`-built
  code, dynamic property names, decorators that transform values, Web Workers, iframes of other
  applications.
- **RxJS**: only the operators listed in the docs; others (\`scan\`, \`reduce\`, \`combineLatest\`,
  \`withLatestFrom\`, \`mergeWith\`, custom operators, \`interval\`/\`timer\` factories …) stop the trace
  with an \`unsupported-construct\` diagnostic.
- **Signals**: \`input()\`, \`input.required()\` and \`model()\` values come from parent bindings, which
  are not followed (reported as unresolved). \`effect()\` side effects are not modeled as writes.
- **Templates**: inline templates must be static strings; templates built at runtime are skipped
  with a diagnostic. Template expressions are not type-checked; only element/attribute structure
  and user-input bindings are used. Location mapping for inline templates containing escape
  sequences can be off by a few columns.
- **Unmodeled library calls** propagate argument taint with reduced confidence — this can create
  false positives (a library that escapes its input) and the absence of a model can hide others.
- **Validation logic** in separate functions is not interpreted; only recognized sanitizers,
  configured \`trustedSanitizers\` and the guard patterns each rule documents are credited.
- **Without installed dependencies**, framework APIs are identified from import declarations. This
  is reliable for direct usage but misses types flowing through generic helpers or re-exported
  wrappers (an \`unresolved-imports\` diagnostic is emitted).

## Rule-specific limitations
`;

const rules = builtinRules.map((r) => `\n### ${r.meta.id} — ${r.meta.name}\n\n` + r.meta.docs.limitations.map((l) => `- ${l}`).join('\n')
  + (r.meta.docs.falsePositives.length ? '\n\nPossible false positives:\n\n' + r.meta.docs.falsePositives.map((l) => `- ${l}`).join('\n') : '')).join('\n');
writeFileSync(new URL('../docs/LIMITATIONS.md', import.meta.url), `${ENGINE}${rules}\n\n_Generated from rule metadata in \`packages/rules\` by \`scripts/generate-limitations.mjs\`._\n`);
