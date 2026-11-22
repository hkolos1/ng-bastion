---
title: CI/CD
description: Run NgBastion as a security gate in GitHub Actions, GitLab CI, Jenkins and Azure DevOps, with SARIF upload to GitHub code scanning.
---

Ready-to-copy templates live in the repository under `ci-templates/`:

| File | Platform | Reports |
|---|---|---|
| `ci-templates/github-actions.yml` | GitHub Actions | SARIF uploaded to GitHub code scanning, JSON artifact |
| `ci-templates/gitlab-ci.yml` | GitLab CI | JSON and SARIF artifacts |
| `ci-templates/Jenkinsfile` | Jenkins (declarative) | archived JSON and SARIF |
| `ci-templates/azure-pipelines.yml` | Azure DevOps | SARIF published as `CodeAnalysisLogs` |

:::note[Installation status]
The npm package is not published yet. The templates read the command from `NGBASTION_CMD`; point it at a local build until publication.
:::

## Gates and exit codes

The gate is the exit code of `ngbastion scan`:

| Code | Handling |
|---|---|
| `0` | Pass |
| `1` | Security gate failed — fail the job |
| `2` | Configuration or execution error — always fail; the results are incomplete |

Choose the threshold with `--fail-on` or `failOn` in configuration. When a pipeline needs two formats, the templates produce the second report with `--fail-on none` so that a single run decides the gate.

## GitHub code scanning

`ngbastion scan --format sarif --output ngbastion.sarif`, then upload the file with `github/codeql-action/upload-sarif`. The job needs `security-events: write`. Results carry stable `partialFingerprints`, so alerts are tracked across commits, and traces appear as code flows.

## Recommendations

- Install the project's dependencies before scanning for full type information.
- Keep reports as build artifacts; they contain no absolute paths or secret values.
- Use least-privilege permissions; NgBastion needs no tokens or network access to scan.
