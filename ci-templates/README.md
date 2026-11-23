# CI/CD templates

Ready-to-copy pipelines that run `ngbastion scan` as a security gate and keep the reports as artifacts.

Each template reads the command from `NGBASTION_CMD` (default `npx --yes ngbastion@0.1.0`).
Pin the version you have tested, or point it at a locally installed `ngbastion`.

| File | Platform | Gate | Reports |
|---|---|---|---|
| `github-actions.yml` | GitHub Actions | exit code (`--fail-on`) | SARIF → GitHub code scanning, JSON artifact |
| `gitlab-ci.yml` | GitLab CI | exit code | JSON + SARIF artifacts |
| `Jenkinsfile` | Jenkins (declarative) | exit code → build result | archived JSON + SARIF |
| `azure-pipelines.yml` | Azure DevOps | exit code | published `CodeAnalysisLogs` artifact (SARIF) |

## Exit codes

| Code | Meaning | Recommended handling |
|---|---|---|
| `0` | Scan completed; no finding at or above `failOn` from an `error`-level rule | pass |
| `1` | Security gate failed | fail the job (or mark unstable) |
| `2` | Configuration or execution error (invalid config, plugin failure, missing project, crashed rule) | always fail: results are incomplete |

Each template runs the scan **twice** only when it needs two formats; the second invocation uses
`--fail-on none` so the gate decision comes from a single run. Reports never contain absolute paths,
and secret-looking values are redacted (NGB018).
