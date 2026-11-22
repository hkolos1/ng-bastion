---
title: Limitations
description: What NgBastion 0.1 does not analyze, and where false positives and false negatives can come from.
---

NgBastion reports the patterns it models. The following are known gaps.

## Analysis scope

- Static analysis only: runtime behaviour, server responses and deployment configuration are not observed. Response headers such as CSP are assessed only when they appear in the repository (`index.html`, constant header values in server code, hosting configs); otherwise CSP is reported as not assessed.
- Values of component `input()`, `model()` and `@Input()` properties are not followed into parent templates.
- RxJS support is limited to the operators listed in [Security engine](/docs/security-engine/#rxjs). Other operators (for example `scan`, `withLatestFrom`, `reduce`) stop traces; `combineLatest`, `forkJoin` and `zip` are modeled element-insensitively, which lowers confidence.
- State libraries (NgRx, NGXS, Akita), `Map`/`Set` contents, closures captured in callbacks invoked by libraries, and dependency-injection tokens providing values are not followed.
- Arrays and spread objects are element-insensitive (approximations lower confidence).
- Validation is credited only when it appears as a guard around the sink in the same function (and, for message handlers, one level into helper calls). Validators in other functions are not analyzed and lower confidence instead.
- Third-party DOM helpers (jQuery, custom renderers), MessagePort/Worker/BroadcastChannel messaging, and storage wrappers (localForage, idb) are not modeled.

## Potential false positives

- HTTP responses from your own backend are treated as untrusted (medium trust). If the backend guarantees sanitized content, document an exception.
- Name-based sensitivity (tokens, card data, secrets in NGB006, NGB014–NGB018, NGB020) can match values that are not sensitive.
- Calls into unmodeled libraries propagate taint from their arguments with reduced confidence.

## Potential false negatives

- Sensitive values stored under neutral names without type information.
- Data flowing through unsupported operators, untyped `any` events, or code outside the configured projects.
- Traces cut by analysis limits (reported as `analysis-incomplete`).

## Performance

Each Angular project is analyzed in one TypeScript program. Traces are cached per sink and bounded by the [limits](/docs/configuration/#limits); very large monorepos may need higher limits or `--project` to scan apps separately.
