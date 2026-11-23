# Performance

Measured with `node scripts/benchmark.mjs` (generated Angular-style workspaces: one service + one
component with a signal-based template per feature; every 10th feature contains a real
query-parameter → service → `computed()` → `innerHTML` flow). All 50 rules enabled,
`minConfidence: low`, no `node_modules` (declaration-based identification).

Machine: Apple M3 Max, macOS, Node.js v24.22.0 (2026-11-23).

| Features | Files | Scan time (20 rules, 0.1.2) | Scan time (50 rules) | Seeded flows found | Truncated traces | RSS |
|---:|---:|---:|---:|---:|---:|---:|
| 50 | 100 | 0.36 s | 0.33 s | 5 / 5 | 0 | 301 MB |
| 200 | 400 | 0.56 s | 0.48 s | 20 / 20 | 0 | 369 MB |
| 800 | 1,600 | 1.79 s | 1.30 s | 80 / 80 | 0 | 502 MB |

Going from 20 to 50 rules first made the 1,600-file workspace 87 % slower (3.34 s): every rule that
walks all calls re-resolved callee and receiver types. `Symbols.callee()` and `typeOrigin()` are now
memoized per node, which made scans faster than with 20 rules.

Notes:

- Scan time grows roughly linearly with project size on these workloads; most time is TypeScript
  program creation and type checking of reachable declarations (the first rule to run pays for
  lazy checker work, so per-rule timings are not additive).
- Traces are demand-driven (only sinks are traced) and memoized per node and sink context, so
  rules sharing a sink (e.g. NGB011/NGB012) do not repeat work.
- The benchmark is synthetic. Real projects with deep call graphs or very large `node_modules`
  type graphs will be slower; tune `limits` and watch for `analysis-incomplete` diagnostics.

## Real-world check (50 rules)

Public Angular code bases, cloned without installing dependencies (declaration-based
identification), scanned with `--min-confidence low` and every rule enabled. Nothing was modified
or vendored into this repository. Times are the engine's `durationMs`.

| Project | Angular | Files | 0.1.2 (20 rules) | 50 rules | RSS | Findings 0.1.2 → now | Confidence (high / medium / low) |
|---|---|---:|---:|---:|---:|---|---|
| [angular-realworld-example-app](https://github.com/gothinkster/angular-realworld-example-app) | 21 | 41 | 0.36 s | 0.34 s | 328 MB | 1 → 7 | 3 / 3 / 1 |
| [jhipster-sample-app](https://github.com/jhipster/jhipster-sample-app) | 22 | 168 | 0.69 s | 0.69 s | 366 MB | 4 → 4 | 3 / 0 / 1 |
| [ngx-admin](https://github.com/akveo/ngx-admin) | 15 (outside the supported range) | 480 | 1.01 s | 0.96 s | 435 MB | 0 → 1 | 0 / 0 / 1 |
| [bitwarden/clients](https://github.com/bitwarden/clients) `apps/web` | 21 | 692 | 4.10 s | 3.51 s | 855 MB | 23 → 27 | 5 / 13 / 9 |
| bitwarden/clients (whole Nx monorepo, 9 projects) | 21 | 14,220 | 36.8 s | 26.5 s | 2.5 GB | 84 → 70 | 13 / 23 / 34 |

### Reviewed findings of the new rules

| Rule | Where | Verdict |
|---|---|---|
| NGB026 (medium) | realworld: `PUT /articles/${article.slug}` with `slug` from the editor route | True positive by the rule's definition: an encoded `..%2Fuser` slug turns it into `PUT /user` with the user's token |
| NGB026 (low × 3) | realworld: `GET /articles/${slug}` / `/profiles/${username}` | True pattern, low impact (read-only); hidden by default (`minConfidence: medium`) |
| NGB045 (low) | realworld / ngx-admin / bitwarden: CDN stylesheet, Google Fonts / Maps, Stripe.js | True pattern; known evolving providers are low confidence |
| NGB034 (× 4) | bitwarden: `postMessage` target origin taken from a `parent` / `parentOrigin` query parameter | Matches the rule; exploitability depends on how those pages can be framed and was not assessed |
| NGB033 (× 3) | bitwarden: `window.open(url, '_blank')` without `noopener` | True pattern; low severity (two of them open the vendor's own site) |
| NGB027 (low) | bitwarden: `setAttribute('title', subtitle)`; sensitivity only from a name along the data flow | Likely false positive; low confidence, hidden by default |

False positives found during this review were fixed before release, each with a regression test:
NGB027 matched names inside translation-key literals, interpolated attribute text, component inputs
and formatter arguments; NGB028 matched `globalThis.PublicKeyCredential = class …` polyfills; NGB023
missed a `state=` parameter split across string literals; NGB034 / NGB026 treated
`location.origin` and browser-built Fetch `Request.url` as attacker-controlled. The review also
found two pre-existing defects: NGB002 reported every `obj.hasOwnProperty(key)` call (21 false
positives in bitwarden/clients), and NGB009 crashed on `Object.prototype.toString.call(v)`
(`rule-failed` in three projects). Both came from looking up method or type names in plain objects,
where `Object.prototype` members match; they are fixed.

Diagnostics on these projects: `unresolved-imports` (dependencies not installed),
`unsupported-construct` (RxJS operators outside the model), `analysis-incomplete` (one trace limit
hit in bitwarden/clients) and `csp-not-assessed`. Synthetic fixtures and five projects do not show a
false-positive rate; treat the new heuristic rules (warnings in `recommended`) accordingly.
