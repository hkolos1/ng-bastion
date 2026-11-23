---
title: Baselines and fingerprints
description: Create a local baseline, interpret comparable findings and gate changes without suppressing existing issues.
---

## Create and compare

```sh
ngbastion scan --create-baseline
ngbastion scan --baseline .ngbastion-baseline.json --format html -o review.html
ngbastion scan --baseline .ngbastion-baseline.json --update-baseline
```

The default filename is relative to the scanned workspace. Use `--baseline path` with creation or update to choose a path relative to the invoking directory. Creation refuses to replace an existing file. An ordinary comparison only reads it. Updates check the previous snapshot and use a same-directory rename. Unverified disappearances prevent replacement. Keep a reviewed copy in version control when using a baseline for CI decisions.

A baseline contains the scanner version, identity algorithm version, timestamp, configuration digest, observed file and rule coverage, diagnostic codes and minimal finding records. It contains no source excerpts. Paths and rule identifiers can still disclose project information. The [baseline file schema](/schemas/baseline-v1.json) is versioned independently of report JSON.

## Finding fingerprints

Version 2 uses SHA-256 over the rule identifier, normalized project-relative path, significant operation tokens, enclosing named scopes and available source and sink identities. An occurrence index distinguishes identical operations. Whitespace, blank lines and ordinary TypeScript comments outside literals are skipped. Location-only rules use the reported line as a fallback. File renames, substantial operation edits, changes to the source or sink and reordering identical operations can change identity. V1 fingerprints continue to work for existing exceptions.

## Interpret status

| Status | Interpretation |
|---|---|
| New | Current active finding absent from comparable prior coverage |
| Existing | Active in both scans with the same fingerprint |
| Resolved | Prior active finding absent from comparable current coverage |
| Uncertain | A current finding has no active match and prior coverage cannot establish its absence |
| Unverified disappearance | A prior finding lacks a current match and its absence cannot be assessed reliably |

A change to eligibility, file coverage, configuration, scanner version or analysis completeness can limit comparison. A matching hidden or suppressed operation prevents a confirmed disappearance. The report keeps existing findings visible and reports suppression separately. A resolved observation still requires engineering review.

## Security gates

```sh
ngbastion scan --baseline .ngbastion-baseline.json --fail-on high --fail-on-status new
ngbastion scan --fail-on high --fail-on-confidence high
```

The default severity gate evaluates active findings from error-level rules. Severity increases from info to low, medium, high and critical. The threshold is inclusive. Confidence increases from low to medium to high. `--min-confidence` affects visibility. `--fail-on-confidence` narrows only the gate.

The new-status gate includes uncertain current findings to avoid silently passing incomplete comparisons. It requires a compatible baseline. Policies with mandatory rules or a severity ceiling reject scoped gates. Exit 0 means the gate passed or was disabled, exit 1 means the gate failed and exit 2 signals a configuration, comparison or execution error.
