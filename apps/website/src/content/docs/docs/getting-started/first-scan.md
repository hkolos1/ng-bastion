---
title: First scan
description: Run NgBastion on an Angular workspace, understand the output and choose a security gate.
---

From the root of an Angular workspace (the folder with `angular.json`):

```sh
ngbastion scan
```

NgBastion discovers projects from `angular.json` and uses each project's `tsConfig`. Without `angular.json` it uses `tsconfig.json`; without that, it analyzes every `.ts` file in the folder. Use `--project <name>` to limit a monorepo scan.

With no configuration file, the [`recommended` preset](/docs/configuration/#presets) applies: every rule is enabled, findings below medium confidence are hidden, and the gate fails on `high` or worse.

## The output

Each finding shows:

1. severity, rule ID, rule name, confidence and how the finding was established (`dataflow`, `pattern` or `heuristic`);
2. the location and the source line;
3. the message;
4. for data-flow findings, the trace from source to sink;
5. a one-line fix and the `ngbastion explain <ID>` command for details.

The summary lists counts per severity, suppressed findings and how many lower-confidence findings were hidden. The final line states the gate result. Diagnostics — for example `csp-not-assessed` or `analysis-incomplete` — tell you where the analysis was partial.

## Useful next commands

```sh
ngbastion scan --min-confidence low     # include low-confidence findings
ngbastion scan --verbose                # evidence and informational diagnostics
ngbastion explain NGB001                # full documentation of a rule
ngbastion init                          # create a configuration file
```

See the [CLI reference](/docs/cli-reference/) for every option and exit code.
