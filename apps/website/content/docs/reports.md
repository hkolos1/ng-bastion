---
title: Reports
description: Terminal, JSON (schema v1) and SARIF 2.1.0 reports produced by NgBastion.
---

Select a format with `--format terminal|json|sarif` and write it to a file with `--output`.

## Terminal

Concise, human-oriented output: findings sorted by severity and confidence, traces, a one-line fix per finding, diagnostics and the gate result. `--quiet` prints only the summary, `--verbose` adds evidence and informational diagnostics, `--show-suppressed` also lists suppressed findings.

## JSON

A versioned, documented format. The JSON Schema is `packages/cli/schema/report-v1.json` (`schemaVersion: 1`); every report is validated against it in the test suite.

Top-level fields: `tool`, `scan` (time, duration, Angular version, projects, effective `failOn`/`minConfidence`, config sources, stats), `rules`, `findings`, `suppressed`, `diagnostics`, `summary`.

Each finding contains a stable `fingerprint` (independent of line numbers), `ruleId`, `severity`, `confidence`, `evidenceKind`, `level`, `message`, `location`, `snippet`, `trace`, `evidence` and, for suppressed findings, `suppression` with its justification and source.

All paths are relative to the workspace root; reports never include absolute paths.

## SARIF 2.1.0

The SARIF log includes rule metadata with help text, `security-severity` scores for GitHub code scanning (critical 9.5, high 8.0, medium 5.5, low 3.0), results with `partialFingerprints`, `codeFlows` built from traces, suppressions, and tool execution notifications for diagnostics. Output is validated against the official SARIF 2.1.0 schema in the test suite.

## Sensitive values

Reports never print secret values. NGB018 redacts detected secrets to their first four characters and length and omits the source line; payment findings omit the snippet as well.
