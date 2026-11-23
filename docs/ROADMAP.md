# NgBastion roadmap & progress

Status legend: ✅ done · 🚧 in progress · ⏳ planned · ⏸ deferred (needs explicit approval)

| Phase | Scope | Status |
|---|---|---|
| 1 | Foundation: pnpm + Turborepo monorepo, TS/tsup/Vitest/ESLint, package boundaries, CLI skeleton, CI | ✅ |
| 2 | Type-aware data-flow engine (TS Compiler API, Angular templates, taint, RxJS/signals, limits) | ✅ |
| 3 | Rules NGB001–NGB020 with positive/negative/false-positive tests | ✅ |
| 4 | CLI (init/scan/explain/rules/doctor), hybrid config, presets, policies, plugins, reporters | ✅ |
| 5 | Compatibility (Angular 20/21/22), regression, SARIF validation, coverage, CI templates | ✅ |
| 6 | README, docs site, landing page, playground, logo, SEO, changelog | ✅ (site on Firebase Hosting) |
| 7 | Rules NGB021–NGB050 in three batches, engine extensions, real-world validation ([RULE-EXPANSION.md](RULE-EXPANSION.md)) | ✅ (unreleased) |

## Released

- 0.1.0 published to npm (`ngbastion`, `@ngbastion/*`) on 2026-11-23; repository public

## Deferred (require explicit approval)
- Trusted Publishing, release automation, public GitHub releases
- Custom domain (ngbastion.dev), announcements

## Next milestone: NGB051–NGB100 (not started)

Stabilize the 50-rule release first: collect false-positive reports for the new heuristic rules and
decide which of them can move from `warn` to `error`. New rules should cover new Angular / frontend
categories (e.g. Workbox caching, NgRx / signal-store state persistence, Web Worker messaging,
WebAuthn / Credential Management misuse, CORS configuration in SSR servers), not split existing ones.

## Next candidates (post 0.1.0)

- ESLint plugin and IDE integration reusing `@ngbastion/core`
- More RxJS operators (`combineLatest`, `withLatestFrom`, `scan`) and NgRx selectors
- Following `input()` bindings from parent templates
- Guard credit for validation helpers via function summaries
