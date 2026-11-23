---
title: Configuration
description: Configure NgBastion with JSON or TypeScript, presets, severity overrides, shared configurations, organizational policies and exceptions.
---

NgBastion works without configuration. To customize it, create one of these files in the workspace root (`ngbastion init` does this for you):

- `ngbastion.config.json`
- `ngbastion.config.ts` (also `.mts`, `.js`, `.mjs`)

Exactly one may exist; NgBastion stops with an error when it finds several. Both formats resolve into the same validated schema, and every invalid property is reported with its path (for example `rules.NGB001: expected 'error' | 'warn' | 'off' or an object`).

:::caution[TypeScript configs execute code]
`ngbastion.config.ts` is imported with Node.js' built-in type stripping, so loading it runs it. Keep it free of side effects and treat it like any other build script. NgBastion never downloads or executes remote configuration.
:::

## JSON

```json
{
  "extends": ["recommended"],
  "rules": {
    "NGB001": "error",
    "NGB014": "warn",
    "NGB020": "off",
    "NGB016": { "level": "error", "severity": "critical" }
  },
  "exclude": ["**/*.spec.ts", "dist/**"],
  "failOn": "high"
}
```

## TypeScript

```ts
import { defineConfig } from 'ngbastion/config';

export default defineConfig({
  extends: ['recommended'],
  rules: { NGB014: 'warn' },
  exclude: ['**/*.spec.ts', 'dist/**'],
  failOn: 'high',
});
```

`defineConfig` only provides type checking; the object is used as-is.

## Options

| Option | Description |
|---|---|
| `extends` | Presets, relative files or installed packages, applied in order. When omitted, `["recommended"]` is assumed; use `[]` to start empty. |
| `rules` | Per rule: `"error"`, `"warn"`, `"off"`, or `{ level, severity, options }`. Findings from `warn` rules are reported but never fail the gate. |
| `include` / `exclude` | Globs relative to the workspace root. Exclusions from all layers are combined. |
| `projects` | `angular.json` project names to scan (default: all). |
| `failOn` | Gate threshold: `critical`, `high`, `medium`, `low`, `info` or `none`. |
| `minConfidence` | Hide findings below `high`, `medium` or `low`. |
| `limits` | Analysis limits, see below. |
| `trustedSanitizers` | Project functions treated as sanitizers for every context, as `path/to/file.ts#name` or `name`. Review them first: unknown sanitizers are never trusted automatically. |
| `plugins` | Trusted [plugin](/docs/plugin-api/) modules. |
| `exceptions` | Narrow, justified suppressions (below). |
| `policy` | Organizational constraints (below). |

## Presets

| Preset | Rules | `failOn` | `minConfidence` | Policy |
|---|---|---|---|---|
| `recommended` | Every built-in rule as `error`, except the context-dependent or heuristic rules NGB008, NGB010, NGB019, NGB022, NGB027, NGB028, NGB030 as `warn`; excludes `*.spec.ts`, `*.test.ts`, `e2e`, `cypress`, `playwright` | `high` | `medium` | none |
| `strict` | All 20 as `error`; same exclusions | `medium` | `low` | none |
| `enterprise` | Extends `strict` | `high` | `medium` | Mandatory NGB001–NGB005, NGB007, NGB011, NGB013–NGB016, NGB018, NGB020; `maxFailOn: high`; no inline suppressions; exceptions must expire within 180 days |
| `payments` | Extends `recommended`; NGB013–NGB018 as `error` | `high` | `low` | Mandatory NGB013, NGB015, NGB016, NGB017, NGB018; exceptions must expire |

The `payments` preset raises visibility of payment and credential findings. It does not certify PCI DSS or any other compliance.

## Shared configurations

`extends` accepts relative files (`"./security/base.json"`) and locally installed packages (`"@acme/ngbastion-config"`). Packages are resolved with Node.js module resolution from the extending file; nothing is downloaded, and `https://…` entries are rejected. Circular `extends` chains are reported as errors.

## Precedence

1. Presets and shared configs, in `extends` order
2. The configuration file itself
3. CLI flags (`--fail-on`, `--min-confidence`, `--project`)
4. Policy constraints, applied last

## Organizational policies

A shared configuration can declare a `policy`. Policies only ever tighten: a later layer cannot loosen one.

```json
{
  "policy": {
    "name": "acme-frontend",
    "mandatoryRules": ["NGB001", "NGB003", "NGB013"],
    "maxFailOn": "high",
    "allowInlineSuppressions": false,
    "requireExceptionExpiry": true,
    "maxExceptionDays": 90
  }
}
```

- A mandatory rule set to `off` or `warn` stays `error`, and a `policy-violation` warning names the policy.
- A `failOn` looser than `maxFailOn` (including `none`) is replaced by `maxFailOn`, with a warning.
- With `allowInlineSuppressions: false`, inline comments are ignored and reported.
- Exceptions without a required expiry, or expiring later than `maxExceptionDays`, are ignored and reported.

## Exceptions

```json
{
  "exceptions": [
    {
      "rule": "NGB003",
      "files": ["src/app/legacy/widget.ts"],
      "justification": "Renders only admin-authored fragments; tracked in SEC-142",
      "expires": "2027-03-31",
      "line": 42
    }
  ]
}
```

- `rule`, `files` and a `justification` of at least 10 characters are required. `line` and `fingerprint` (from the JSON/SARIF report) narrow it further.
- Globs matching the whole workspace (`**`, `**/*`) are rejected.
- After the `expires` date the exception no longer applies: the findings are reported again and an `exception-expired` warning is shown.
- Suppressed findings remain in JSON and SARIF output with their justification.

### Inline suppressions

```ts
// ngbastion-ignore-next-line NGB003 -- renders a constant template from the CMS build step
el.innerHTML = trustedFragment;

el.innerHTML = other; // ngbastion-ignore NGB003 -- reviewed in SEC-88
```

A justification after `--` is required; without one the comment is ignored and a warning is shown. Several IDs can be listed, separated by commas.

## Limits

| Limit | Default | Meaning |
|---|---|---|
| `maxDepth` | 40 | Propagation steps per trace |
| `maxCallSites` | 25 | Call sites followed for one parameter |
| `maxFileHops` | 12 | File changes along one trace |
| `maxVisitedNodes` | 20000 | Expressions visited per trace |
| `maxPathsPerSink` | 5 | Flows kept per sink |
| `maxTimeMs` | 120000 | Wall-clock budget per project |

When a trace stops at a limit, the scan reports `analysis-incomplete` (or `analysis-timeout`) instead of silently dropping paths.
