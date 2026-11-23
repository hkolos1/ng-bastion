# Reporting Release validation

## Developer workflow

Generate the local artifact, establish a reviewed baseline, inspect Git associations and compare completed scans with these commands.

```sh
ngbastion scan --format html --output security-report.html
ngbastion scan --create-baseline
ngbastion scan --baseline .ngbastion-baseline.json --fail-on high --fail-on-status new
ngbastion scan --baseline .ngbastion-baseline.json --update-baseline
ngbastion scan --diff origin/main --format json --output current.json
ngbastion report compare previous.json current.json --format json --output changes.json
```

The HTML file opens directly from disk. It includes severity and confidence distributions, diagnostics, suppression and gate information, comparison counts when available, a searchable findings explorer, ordered trace steps, syntax-highlighted excerpts, remediation and print styles. The website reference includes a screenshot of the generated showcase report.

## Architecture and compatibility

The existing ScanResult remains the reporter input. The scanner records unique completed rules, observed paths, effective project settings and v2 operation identities. The CLI derives a versioned snapshot, compares active findings, applies explicit gate restrictions and adds optional Git labels. These operations preserve original findings. Machine-readable JSON retains its closed v1 finding objects. New identity maps, snapshots, classifications and gate scope use the existing extensible scan object. SARIF retains v1 partial fingerprints and carries v2 fingerprints, standard comparable baseline states, code flows and supplemental properties. V1 exceptions remain usable.

The baseline file contains minimal comparison records. Create and update are explicit commands. An exclusive lock serializes writers, creation uses an exclusive link, and an update verifies the previous snapshot before atomic replacement. Ordinary comparisons are read-only. Unverified disappearances block replacement.

## Regression and field checks

- The Phase 0 audit verified 100 sequential built-in rules and 552 passing registry and rule tests.
- The milestone regression suite passed 658 tests, including Angular 20, 21 and 22 compatibility, CLI exit behavior, JSON/SARIF schema validation, stable identity, baseline round trips, scoped gates, multi-file Git associations, invalid input and comparison.
- The website passed 154 tests. The static build verified 120 routes and internal links. Website docs include two downloadable schemas, the screenshot and generated CLI help.
- The vulnerable showcase produced 113 active findings in 35 TypeScript files. The severity gate returned 1. Comparing an unchanged repeat scan produced 113 existing findings, zero new findings and zero resolved findings. The new-status gate returned 0. HTML, JSON and SARIF artifacts were generated locally.
- The repository's Angular/Analog website scan analyzed 43 TypeScript files and 17 templates. It produced zero active findings and a CSP assessment diagnostic. That observation is limited to the scanner's coverage.

## Offline browser measurements

One macOS run with Node 24.22.0 and desktop Chromium opened each report via a file URL in an offline browser context. The fixtures included repeated findings, a long file path, hostile strings and a 60-step trace. Filtering uses cached search text and a cached ordering. Only the current 50 rows are attached interactively. Printing expands the filtered selection across all pages.

| Findings | HTML bytes | Generate | Load | Filter | JS heap | Generator RSS change |
|---:|---:|---:|---:|---:|---:|---:|
| 0 | 73,234 | 3 ms | 29 ms | <1 ms | 3.0 MB | 0.3 MB |
| 4 | 107,379 | 2 ms | 25 ms | <1 ms | 5.2 MB | 0.5 MB |
| 350 | 1,171,495 | 8 ms | 33 ms | 1 ms | 6.5 MB | 6.4 MB |
| 2,000 | 6,259,218 | 39 ms | 217 ms | 2 ms | 12.4 MB | 22.6 MB |

Measurements are samples. Browser heap excludes native DOM and graphics allocations. RSS change samples the Node process immediately before and after generation. It is sensitive to allocator reuse. The file includes static details for readers with JavaScript disabled, so total size and initial parsing grow with the number and length of findings.

## Security and accessibility review

Browser checks exercised hostile content, CSP enforcement during normal operation, zero network requests, accessible filter controls, keyboard expansion, themes, pagination, a long trace, local PDF creation and a mobile-width JavaScript-disabled fallback. Source, paths and metadata are encoded before insertion into markup. Browser interaction uses DOM methods. Scripts and styles are hash-authorized. Links to built-in rule pages use a fixed HTTPS origin. The embedded font includes its license.

HTML sharing mode omits source and dynamic evidence text. Additional trace excerpts are restricted to simple expressions already loaded by TypeScript. A sensitive finding prevents these extra excerpts from being emitted for its file. Project names, paths and rule metadata still identify the scanned project. Git uses local data, disables external diff, text conversion, filesystem monitoring and configured content filters, and applies a 64 MiB subprocess output limit.

## Interpretation limits

- Rule applicability remains unmeasured. A completed evaluation can encounter zero relevant operations.
- A v2 fingerprint uses the rule, path, significant operation tokens, named scope, source/sink identity and an occurrence index. Renames, major refactoring or reordering identical operations can change it. Rules with only a location use a tokenized line fallback.
- Compare scans from the same logical workspace. Identical fingerprints establish a match even when severity or confidence changes. Missing or changed coverage, diagnostics and suppressed or hidden identities can make unmatched observations uncertain. This deliberately favors inconclusive results over false resolution claims.
- Git associations describe working-tree locations and recorded trace steps. There is no base-revision build, installation or rescan. Unstaged moves may appear as a deletion and addition. A missing or ignored trace step cannot contribute a changed-line association.
- Chromium ran the full browser suite. Separate offline smoke tests opened the actual showcase report in Firefox 159 and WebKit 27.2 and verified keyboard expansion, severity filtering, reset and theme switching. Manual screen-reader testing remains outstanding.

## Release steps

Use the minor changesets for the fixed public package group. From 0.1.2 the proposed reporting line is 0.2.0, subject to maintainer review of all pending changesets. Review the package tarballs, release notes and Hosting preview separately. A push to main runs CI. A v-prefixed tag starts npm publication and public release creation, so create one only after publication approval. Production Firebase Hosting is a separate approval and deployment step.
