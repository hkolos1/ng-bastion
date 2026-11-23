# Reporting release implementation plan

## Phase 0 audit

Base revision 97ce814 on main. The built CLI lists 100 rules, NGB001 through NGB100. Vitest passed all 552 tests in the 100 per-rule suites and registry suite. The registry validates sequential IDs, preset agreement and documentation. The older diagram in ARCHITECTURE.md predates the expansion.

The CLI uses Node parseArgs and dispatches scan, init, rules, explain and doctor. Scan accepts a directory, format, output, config, project selection, severity threshold, confidence floor and terminal display controls. The core ScanResult already normalizes workspace-relative locations, independent severity and confidence, optional single-line snippets, ordered typed trace steps, evidence kind, diagnostics, active and suppressed findings. The core counts unique TypeScript source files and separately counts templates. Enabled rules can return without encountering any relevant API. Rule applicability has no signal in the plugin contract.

Terminal supports a summary, suppressions and verbose evidence. JSON v1 and SARIF 2.1.0 already carry the existing fingerprint. SARIF uses partialFingerprints and codeFlows. The current fingerprint depends on line text and an occurrence number. Config exceptions may depend on it. Preserve that lookup during identity migration.

Recommended, strict, payments and enterprise presets resolve before scanning. Inline suppressions require justification. Config exceptions support scope, fingerprint and expiry. Mandatory rules and policy ceilings constrain configuration. Confidence filtering precedes gating. Error-level active findings at or above failOn fail the gate. Exit codes are 0 for success, 1 for a gate failure and 2 for configuration or execution errors.

Vitest covers individual rules, core, config, CLI integration, schemas, showcase, self-scan and Angular 20–22 compatibility. The Analog site has its own tests, rule pages, playground and static build verification. CI builds and tests pull requests and main. A v* tag triggers npm publication and a GitHub release. The website README documents manual Firebase deployment. Keep review branches untagged.

## Review sequence

1. **Foundation.** Extend ScanResult with observed rule coverage. Project the existing result into an HTML-specific read model. Render an offline overview, filters, paged findings, ordered trace, code line and remediation. Preserve snippet redaction. Use text-context encoding, fixed-origin documentation links and hashed static assets. Exercise injection cases, real CLI output, browser interaction and the full regression suite before opening the foundation PR.
2. **Identity and baselines.** Version a semantic fingerprint alongside v1, test edits and repeated operations, introduce an atomic explicit baseline writer and validate its schema. Record comparable coverage, configuration and failures. Gate new findings only with a compatible comparison and preserve mandatory enterprise policy. Validate both machine formats and document exit behavior.
3. **Local Git and comparison.** Classify full-scan findings by changed paths and hunks using argument-array Git calls and NUL-delimited paths. Include trace locations. Compare saved reports by compatible fingerprint, retaining uncertain disappearances. Exercise renames, deletions, untracked files, invalid revisions and monorepos.
4. **Release validation.** Benchmark generation, local opening, filtering and memory on zero through thousands of findings. Test keyboard, themes, print and long traces. Update existing CLI and website docs with measured behavior and a real report preview. Run schema, compatibility, site and browser tests. Prepare changesets for review. Publication and production deployment require separate approval.

Each batch gets its own review boundary. Unknown applicability, missing trace steps and absent comparison data must stay explicit throughout.

## Batch 1 validation

The showcase scan produced 113 active findings across 35 TypeScript files with the default configuration. It returned gate exit code 1 and wrote the report. The HTML overview counts findings after policy and confidence filtering. Suppressed entries are available in the explorer. Snippets show the engine's retained finding line. Trace locations and descriptions come from ordered scanner evidence. The engine currently reports analysis limits at scan scope and supplies no sanitizer or validation nodes beyond its existing step kinds.

[Showcase overview](reporting/showcase-overview.png) · [Catalog severity menu, dark](reporting/ngb-dropdown-dark.png) · [Catalog severity menu, light](reporting/ngb-dropdown-light.png)

Chromium opened local files offline, exercised search, sorting, filtering, keyboard expansion, theme switching and print. A hostile text fixture remained inert. The browser run recorded the following sample on macOS with Node 24.22.0. Load time includes parsing and indexing. Search measures the synchronous input handler. Heap is a Chromium JavaScript heap sample after interaction and excludes native DOM and renderer memory.

| Findings | HTML bytes | Generate | Local load | Search | JS heap |
|---:|---:|---:|---:|---:|---:|
| 0 | 72,470 | 1 ms | 30 ms | <1 ms | 3.0 MB |
| 4 | 101,999 | 1 ms | 29 ms | <1 ms | 5.4 MB |
| 350 | 1,146,389 | 5 ms | 49 ms | 1 ms | 8.8 MB |
| 2,000 | 6,140,060 | 52 ms | 214 ms | 3 ms | 11.2 MB |

Source snippets remain sensitive project data. Redact-source mode also omits free-text evidence. Paths, project names and rule documentation remain available to reviewers. The CSP allows the packaged hashed script and stylesheet and the embedded font. Links to built-in documentation use a fixed HTTPS origin. The reporter renders text and quoted attributes with encoding and indexes the resulting elements locally. The scan result remains usable by all existing reporters.

Use a minor changeset for the fixed package group. Review Batch 1 before integrating identity changes. Release tagging, npm publication and production Hosting deployment remain separate release decisions.
