# Architecture

```
            ┌──────────────┐     ┌────────────────┐
  user ───▶ │ ngbastion    │────▶│ @ngbastion/    │  load, validate, presets,
            │ (packages/   │     │ config         │  extends, policies, exceptions
            │  cli)        │     └────────────────┘
            │ reporters:   │     ┌────────────────┐
            │ terminal,    │────▶│ @ngbastion/    │  builtinRules NGB001–NGB020
            │ JSON, SARIF  │     │ rules          │──┐ (depend only on plugin-api)
            └──────┬───────┘     └────────────────┘  │
                   │ scan()                           │ SecurityRule.analyze(ctx)
                   ▼                                  ▼
            ┌───────────────────────────────────────────────────┐
            │ @ngbastion/core                                    │
            │ workspace discovery → ts.Program → CodeIndex        │
            │ templates (@angular/compiler) → TaintEngine         │
            │ AnalysisContext → rules → normalize → gate          │
            └───────────────────────────────────────────────────┘
                   ▲ implements
            ┌──────┴─────────┐
            │ @ngbastion/    │  versioned contract (PLUGIN_API_VERSION = 1)
            │ plugin-api     │  used by built-in and third-party rules
            └────────────────┘
```

The engine has no CLI concerns (no process exit, no terminal output) and accepts in-memory files,
so future ESLint plugins, IDE integrations and the website generator reuse it unchanged.

## Scan pipeline (`packages/core/src/scan.ts`)

1. **Workspace discovery** — `angular.json` projects (`build.options.tsConfig`, `index`), solution-style
   `tsconfig.json` with references, or a directory fallback. Angular version from installed
   `@angular/core` (or the declared range).
2. **Program** — one `ts.Program` per project, emit disabled, `skipLibCheck`. The bundled TypeScript
   6.0 parses Angular 20–22 sources; the scanned project's TypeScript version is irrelevant.
3. **CodeIndex** — a single AST pass collects calls, `new` expressions, assignments, classes and
   string literals. Call-site, write and method-call maps are built lazily, once per scan.
4. **Templates** — `@Component` metadata (inline or `templateUrl`) is parsed with
   `@angular/compiler`'s `parseTemplate`. Rules get a simplified element/attribute model; the
   engine gets template user-input bindings (`[(ngModel)]`, `(input)="x = $event.target.value"`).
5. **Rules** run against a read-only `AnalysisContext` (program, checker, index, templates, taint
   analyzer, symbol resolver, guard helpers). A crashing rule becomes an `error` diagnostic.
6. **Normalization** — relative paths, snippets (redactable), stable fingerprints
   (rule + file + normalized line text + occurrence), confidence filter, inline suppressions,
   config exceptions (with expiry), deduplication across projects, security gate.

## Symbol identification (`symbols.ts`)

`typeOrigin(expr)` returns `{ module, name, resolvedBy }`:

- **type-checker**: the declaration's file decides the module (`@angular/common`, `dom`, `lib`, or a
  project file). Entry-point specifiers (`@angular/common/http`) match their package.
- **declaration**: when dependencies are not installed, type annotations, `inject(X)`,
  `new X()` and import specifiers recover the module. A project function named `eval` or a class
  with a `bypassSecurityTrustHtml` method never matches the real API.

## Taint engine (`taint/engine.ts`)

Demand-driven **backward** analysis: rules ask `trace(sinkArgument, { context })`. The engine walks
back through:

| Construct | Behaviour |
|---|---|
| variables, `let` reassignments, destructuring | all initializers and writes |
| function parameters | bound arguments (context-sensitive when entered from a call), otherwise all call sites (≤ `maxCallSites`) and callback references |
| return values | each `return`, with parameters bound to the call's arguments |
| class fields / getters / services | initializer + every write anywhere in scope + template user input |
| interface / DTO fields | taint of the containing object |
| string ops, template literals, `+`, `JSON.*`, `decodeURIComponent`, `URL`, `URLSearchParams` | propagate |
| arrays, `Object.assign`, unmodeled library calls | propagate with an *approximation* (lowers confidence) |
| RxJS | `subscribe`, `pipe` with `map`, flattening operators, pass-through operators, `catchError`, `startWith`…, `of`/`from`/`defer`, Subjects, `firstValueFrom` |
| Signals | `signal`/`set`/`update`, `computed`, `linkedSignal`, `toSignal`, `toObservable`; `input()`/`model()` are unresolved (parent-supplied) |
| sanitizers | context-specific (`DomSanitizer.sanitize(SecurityContext.X)`, DOMPurify for HTML, `encodeURIComponent` for HTML/URL, numeric conversion, configured `trustedSanitizers`) |
| `bypassSecurityTrust*` | **pass-through** with a `trust-bypass` step — never a sanitizer |

Results contain flows (source, ordered steps, confidence, approximations), unresolved origins,
sanitized origins, constants, names (for sensitivity heuristics) and a `truncated` flag. Results are
memoized per (node, context).

**Confidence** of a flow = source trust (URL/message/window.name: high; user input/referrer/HTTP:
medium; storage/cookie: low) lowered once per distinct approximation (max two). Rules lower it
further when a sink was matched only by name. **Severity** is the rule's (configurable) impact
rating and is independent of confidence.

## Limits

`maxDepth`, `maxCallSites`, `maxFileHops`, `maxVisitedNodes`, `maxPathsPerSink`, `maxTimeMs` (see
`packages/config/src/presets.ts`). Cycles are cut by an explored set per trace. Any truncation is
reported as `analysis-incomplete` / `analysis-timeout`.
