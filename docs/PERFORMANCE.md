# Performance

Measured with `node scripts/benchmark.mjs` (generated Angular-style workspaces: one service + one
component with a signal-based template per feature; every 10th feature contains a real
query-parameter → service → `computed()` → `innerHTML` flow). All 20 rules enabled,
`minConfidence: low`, no `node_modules` (declaration-based identification).

Machine: Apple M3 Max, macOS, Node.js v24.22.0 (2026-11-22).

| Features | Files | Scan time | Seeded flows found | Truncated traces | RSS |
|---:|---:|---:|---:|---:|---:|
| 50 | 100 | 0.36 s | 5 / 5 | 0 | 350 MB |
| 200 | 400 | 0.56 s | 20 / 20 | 0 | 424 MB |
| 800 | 1,600 | 1.79 s | 80 / 80 | 0 | 561 MB |

Other data points: the vulnerable showcase (12 files, installed Angular 22 types) scans in ≈0.4 s;
each Angular 20/21/22 compatibility fixture in ≈0.4 s.

Notes:

- Scan time grows roughly linearly with project size on these workloads; most time is TypeScript
  program creation and type checking of reachable declarations.
- Traces are demand-driven (only sinks are traced) and memoized per node and sink context, so
  rules sharing a sink (e.g. NGB011/NGB012) do not repeat work.
- The benchmark is synthetic. Real projects with deep call graphs or very large `node_modules`
  type graphs will be slower; tune `limits` and watch for `analysis-incomplete` diagnostics.

## Real-world check

The public [Angular RealWorld example app](https://github.com/realworld-apps/angular-realworld-example-app)
(Angular 21, 41 analyzed files, 18 templates, dependencies not installed) was scanned with
`--min-confidence low`:

| Engine version | Scan time | Findings | Truncated traces |
|---|---:|---|---:|
| before shared empty environments + RxJS combinators | 0.8 s | 1 | 4 (`combineLatest` visited 1,020×) |
| current | 0.3 s | 1 (NGB014: JWT stored in `localStorage` — accurate for that app's design) | 0 |

No false positives were reported. The app was not modified or vendored into this repository.
