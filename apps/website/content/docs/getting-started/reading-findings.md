---
title: Reading findings
description: How NgBastion reports severity, confidence, evidence kinds, data-flow traces and diagnostics.
---

## Severity and confidence are separate

**Severity** describes the impact if the finding is real: `critical`, `high`, `medium`, `low`, `info`. Each rule has a default severity; some findings adjust it (for example a trusted *script* bypass is critical) and configuration can override it.

**Confidence** describes how strongly the evidence supports the finding:

| Confidence | Typical evidence |
|---|---|
| high | A supported path from a high-trust source (URL, `postMessage` data, `window.name`) to a sink, without approximations; or an unambiguous pattern |
| medium | A medium-trust source (HTTP response, user input, referrer), or one approximation along the path |
| low | Storage or cookie sources, several approximations, a sink matched only by name, or a dynamic value whose origin could not be resolved |

The security gate (`failOn`) uses severity. `minConfidence` hides findings below a confidence level and the summary counts them.

## Evidence kinds

- `dataflow` — a source-to-sink path was traced. The trace is included.
- `pattern` — a risky construct on its own, e.g. `allow-scripts` with `allow-same-origin`.
- `heuristic` — name- or shape-based evidence, such as a value that *looks* like a secret, or a sink fed by an unresolved value.

## Traces

Each step has a kind, a location and a description:

| Kind | Meaning |
|---|---|
| `source` | Where the untrusted value enters |
| `assignment` | Stored in a variable, field or destructured binding |
| `argument` | Passed into a function or method parameter |
| `return` | Returned from a function |
| `property` | Read from a class or object property |
| `transform` | Concatenation, template literal, string method, `JSON.parse`, … |
| `reactive` | RxJS operator or subscription |
| `signal` | Signal read, `set()`, `computed()`, `toSignal()` |
| `template` | Angular template binding |
| `trust-bypass` | `bypassSecurityTrust*()` — marks the value trusted without sanitizing |
| `sink` | The security-sensitive operation |

Traces contain only steps the engine actually observed; missing segments are never filled in. Approximations taken (for example "collection element (element-insensitive)") are listed in the evidence and lower the confidence.

## Diagnostics

Diagnostics are not findings. They describe the analysis itself: unresolved imports, template parse errors, unsupported constructs, traces stopped by a limit, CSP not assessed, invalid suppressions, expired exceptions. Error-level diagnostics make the scan exit with code `2`.
