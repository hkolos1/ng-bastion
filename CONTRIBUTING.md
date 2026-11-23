# Contributing to NgBastion

Thanks for helping make Angular applications safer. NgBastion values **correct, explainable
findings over many findings** — please keep that in mind for every change.

## Setup

Requirements: Node.js 24 (or 22.22.3+ for the scanner packages; the website needs Node 24), pnpm 10 (via Corepack).

```bash
corepack enable
pnpm install
pnpm build        # packages + website
pnpm test         # unit, integration and Angular 20/21/22 compatibility suites
pnpm lint
pnpm typecheck
pnpm test:coverage
```

Run the CLI from source after building: `node packages/cli/dist/bin.js scan examples/vulnerable-showcase`.

## Repository layout

| Path | Purpose |
|---|---|
| `packages/plugin-api` | Versioned rule contract (`PLUGIN_API_VERSION`) |
| `packages/config` | Config schema, validation, presets, policies, loading |
| `packages/core` | Workspace discovery, TypeScript program, templates, taint engine, scan orchestration |
| `packages/rules` | Built-in rules NGB001–NGB030 and shared rule helpers |
| `packages/cli` | `ngbastion` command, reporters (terminal, JSON, SARIF) |
| `apps/website` | [ngbastion.web.app](https://ngbastion.web.app): Angular 22 + AnalogJS app (landing, docs, rule pages, playground), statically pre-rendered |
| `examples/angular-{20,21,22}` | Compatibility fixtures with installed framework packages |
| `examples/vulnerable-showcase` | Intentionally vulnerable demo app (never deploy) |
| `tests/` | Integration, compatibility and reliability suites, fixtures, SARIF schema |

## Writing or changing a rule

1. Put the rule in `packages/rules/src/rules/ngbXXX-<slug>.ts` using `defineRule()`.
2. Fill **all** `docs` fields: description, rationale, exact patterns, limitations,
   false-positive considerations, remediation, unsafe/safe example. Docs are rendered by
   `ngbastion explain` and the website — they must describe what the code actually does.
3. Prefer `ctx.taint.trace()` + `reportSink()` for source-to-sink rules; identify APIs through
   `ctx.symbols` (type-aware with import fallback), never by bare function names.
4. Choose confidence honestly: `high` only for supported, precise evidence; label name-based
   evidence `heuristic`. Lower confidence when the sink was matched only by name.
5. Add `packages/rules/test/ngbXXX.test.ts` with **positive, negative, safe-equivalent,
   false-positive regression and (where relevant) cross-file** cases, asserting severity and
   confidence — not just "returns a finding".
6. Never commit real secrets or card data. Use synthetic test values (e.g. `4111111111111111`) and
   build secret-shaped strings at runtime in tests.

## Engine changes

The engine must never invent path segments. If a construct is not modeled, record it as
`unresolved`/`unsupported` so users get a diagnostic. Add tests to
`packages/core/test/dataflow*.test.ts` and keep `tests/compatibility` green.

## Commits and pull requests

- Conventional Commits in English: `feat(rules): …`, `fix(core): …`, `test(cli): …`, `docs: …`.
- One logical change per commit; add a changeset (`pnpm changeset`) for user-visible changes.
- Do not weaken or delete tests to make CI pass. Explain limitations instead of hiding them.
- Fill in the pull request template, including false-positive / false-negative impact.

## Releases

Maintainers only. Contributors add changesets; nothing else is needed.

1. `pnpm changeset version` bumps all published packages together and writes their changelogs.
   Curate the matching section of the root `CHANGELOG.md` (it feeds the website).
2. Commit, then tag and push: `git tag -s vX.Y.Z && git push origin main vX.Y.Z`.
3. `.github/workflows/release.yml` builds, tests, publishes to npm via Trusted Publishing (no tokens)
   and creates the GitHub release. It refuses a tag that does not match the package versions.

The website is deployed separately and manually to Firebase Hosting (see `apps/website/README.md`).
