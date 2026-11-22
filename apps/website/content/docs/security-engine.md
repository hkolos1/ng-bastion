---
title: Security engine
description: How NgBastion's type-aware, bounded, demand-driven data-flow analysis works, and exactly which patterns it supports.
---

The engine (`@ngbastion/core`) is independent of the CLI. It discovers projects, builds one TypeScript program per project, indexes the code in a single pass, parses Angular templates, and answers rule queries such as "where can the value reaching this sink come from?".

## Pipeline

1. **Workspace discovery** — `angular.json` projects and their `tsConfig` (including solution-style tsconfigs with references), then `tsconfig.json`, then a directory fallback.
2. **Program creation** — TypeScript 6 Compiler API, no emit. Syntax errors become `parse-error` diagnostics.
3. **Index** — one traversal collects calls, `new` expressions, assignments, classes and string literals. Call sites, writes and method calls per symbol are built lazily.
4. **Templates** — `@Component` metadata (inline `template` or `templateUrl`) is parsed with `@angular/compiler`. Elements, attributes, bindings and user-input bindings are extracted.
5. **Rules** — each rule receives a read-only `AnalysisContext` and returns findings.
6. **Normalization** — locations, fingerprints, inline suppressions, exceptions, confidence filter and gate.

## Identifying APIs

Rules match symbols, not names. With dependencies installed, the TypeChecker gives the declaring package of a type (`DomSanitizer` from `@angular/platform-browser`). Without them, the resolver follows type annotations, `inject(X)` calls, `new X()` and import declarations to recover the module specifier. A project function that happens to be called `eval` or `bypassSecurityTrustHtml` is not treated as the real API.

## Taint analysis

Analysis is demand-driven and runs backwards from each sink argument. It stops at modeled sources, constants, recognized sanitizers or something it cannot resolve.

### Sources and trust

| Source | Trust |
|---|---|
| `ActivatedRoute` query/route params (`snapshot.queryParams`, `queryParamMap.get()`, `params`, `paramMap`, `fragment`) and the `queryParams`/`queryParamMap`/`params`/`paramMap`/`fragment` observables | high |
| `location.href/search/hash/pathname`, stringified `location`, `document.URL/documentURI/baseURI`, `Router.url`, `Location.path()` (`@angular/common`) | high |
| `MessageEvent.data` (typed, destructured, `fromEvent(…, 'message')`) | high |
| `window.name` | high |
| `document.referrer` | medium |
| Input element `.value`, Angular forms `.value` / `getRawValue()` / `valueChanges`, `[(ngModel)]` and `(input)` template bindings | medium |
| `HttpClient` responses, `fetch()` responses | medium |
| Web Storage reads (`getItem`, property access) | low |
| `document.cookie` | low |

### Propagation

Supported: variables and reassignments; destructuring; class fields written anywhere in the project; getters; function and method parameters (bound to arguments when entering a call, otherwise all visible call sites); return values; callbacks passed by reference (`subscribe(this.handle)`, `.bind(this)`); imported functions across files; services injected via constructor or `inject()`; object literals (per property when the object is a local literal); arrays (element-insensitive); template literals and concatenation; string methods; `JSON.parse/stringify`, `String()`, `decodeURIComponent()`, `atob()`; `new URL()`, `new URLSearchParams()` and their `get()`; `Promise.then()`, `await`, `firstValueFrom()`/`lastValueFrom()`; `for…of`.

Calls into unmodeled libraries propagate from their arguments **with reduced confidence**. Interface methods without a visible implementation are reported as unresolved.

### RxJS

| Supported | Behaviour |
|---|---|
| `map` | Follows the projection's return value |
| `switchMap`, `mergeMap`, `concatMap`, `exhaustMap`, `flatMap` | Follows the returned observable |
| `tap`, `filter`, `take`, `takeUntil`, `takeUntilDestroyed`, `takeWhile`, `first`, `last`, `distinctUntilChanged`, `distinctUntilKeyChanged`, `debounceTime`, `throttleTime`, `auditTime`, `sampleTime`, `delay`, `shareReplay`, `share`, `retry`, `finalize`, `skip`, `skipWhile`, `timeout`, `observeOn`, `subscribeOn`, `single` | Pass-through |
| `startWith`, `defaultIfEmpty`, `endWith` | Pass-through plus their arguments |
| `catchError` | Pass-through plus the fallback observable |
| `of`, `from`, `defer`, `asObservable()`, `toObservable()` | Followed |
| `merge`, `concat`, `race` | Union of the input observables (precise) |
| `combineLatest`, `forkJoin`, `zip` | Any input may reach any element of the emitted tuple/object (element-insensitive approximation, lowers confidence) |
| `Subject`, `BehaviorSubject`, `ReplaySubject`, `AsyncSubject`, `EventEmitter` | All `.next()` / `.emit()` calls, plus the initial value |

Any other operator or factory (`scan`, `withLatestFrom`, `interval`, …) stops the trace with an `unsupported-construct` diagnostic.

### Signals

`signal()` with its initial value and every `.set()` / `.update()`; `computed()`; `linkedSignal()`; `toSignal()` (including `initialValue`); `asReadonly()`. Component `input()` and `model()` values come from parent bindings, which are not followed: they are reported as unresolved.

### Sanitizers and trust boundaries

Sanitizers only count for the security context they protect:

| Sanitizer | Contexts |
|---|---|
| `DomSanitizer.sanitize(SecurityContext.HTML, …)` | HTML |
| `DomSanitizer.sanitize(SecurityContext.URL / RESOURCE_URL / SCRIPT, …)` | that context |
| `DOMPurify.sanitize()` | HTML |
| `encodeURIComponent()` | HTML, URL, resource URL |
| `encodeURI()` | HTML |
| `Number()`, `parseInt()`, `parseFloat()`, `Boolean()`, `Math.*` | all (numeric) |
| `trustedSanitizers` from configuration | all |

`bypassSecurityTrust*()` is **never** a sanitizer: it is recorded as a `trust-bypass` step and propagation continues. Angular's own template sanitization is respected by not treating `[innerHTML]`, `[href]` and similar bindings as sinks. Guards such as origin allowlists, same-origin URL checks and scheme checks are evaluated by the rules that need them (NGB007, NGB011, NGB012, NGB013).

## Bounded analysis

Every trace is limited by depth, visited nodes, file hops, call sites, paths per sink and a per-project time budget ([configurable](/docs/configuration/#limits)). Cycles are detected per trace. When a limit stops a trace, the result is marked truncated and the scan reports `analysis-incomplete`; a timeout reports `analysis-timeout`.

## Confidence

A flow starts with its source's trust and loses one level per distinct approximation (at most two). Rules lower it further when a sink was matched by name only, or when validation is present but incomplete. Severity is set by the rule and configuration, independently.
