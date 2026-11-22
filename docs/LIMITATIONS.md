# Known limitations

NgBastion reports what its bounded model can establish. This page lists what it cannot. Rule
pages (and `ngbastion explain <ID>`) repeat the rule-specific items below.

**No findings does not mean the application is secure.**

## Scope

- Static analysis only: the application is never built, served or executed. Runtime-only facts
  (deployed HTTP headers, CDN rules, server-side authorization, actual cache behaviour, browser
  extensions) are not observable. Where a rule depends on them it says "not assessed".
- Not a replacement for penetration testing, server-side security reviews or dependency (SCA)
  scanning. Vulnerabilities inside third-party packages are out of scope.

## Engine (data flow)

- **Bounded, not complete**: depth, call sites per parameter, file hops, visited nodes, paths per
  sink and total time are limited. Hitting a limit produces `analysis-incomplete` /
  `analysis-timeout`; other paths may exist.
- **Backward and demand-driven**: only sinks that rules ask about are traced.
- **Context-insensitive fallback**: a parameter without a binding context unions all call sites.
- **Field-insensitive containers**: a field read from an untyped object or interface-typed DTO
  inherits the taint of the whole object; arrays and `Object.assign` are element-insensitive.
- **Not followed**: values stored in Maps/Sets, closures captured by unrelated callbacks,
  state-management libraries (NgRx, NGXS, Akita, signal stores), `Reflect`/proxies, `eval`-built
  code, dynamic property names, decorators that transform values, Web Workers, iframes of other
  applications.
- **RxJS**: only the operators listed in the docs; others (`scan`, `reduce`,
  `withLatestFrom`, `mergeWith`, custom operators, `interval`/`timer` factories …) stop the trace
  with an `unsupported-construct` diagnostic. `combineLatest`, `forkJoin` and `zip` are modeled element-insensitively.
- **Signals**: `input()`, `input.required()` and `model()` values come from parent bindings, which
  are not followed (reported as unresolved). `effect()` side effects are not modeled as writes.
- **Templates**: inline templates must be static strings; templates built at runtime are skipped
  with a diagnostic. Template expressions are not type-checked; only element/attribute structure
  and user-input bindings are used. Location mapping for inline templates containing escape
  sequences can be off by a few columns.
- **Unmodeled library calls** propagate argument taint with reduced confidence — this can create
  false positives (a library that escapes its input) and the absence of a model can hide others.
- **Validation logic** in separate functions is not interpreted; only recognized sanitizers,
  configured `trustedSanitizers` and the guard patterns each rule documents are credited.
- **Without installed dependencies**, framework APIs are identified from import declarations. This
  is reliable for direct usage but misses types flowing through generic helpers or re-exported
  wrappers (an `unresolved-imports` diagnostic is emitted).

## Rule-specific limitations

### NGB001 — Unsafe HTML trust bypass

- Values coming from component `input()`s or `@Input()`s are reported as unresolved (the parent binding is not followed).
- Data flowing through unmodeled libraries is propagated with reduced confidence; data stored in Maps, global state libraries (NgRx, NGXS) or closures is not followed.
- Validation in a separate function (e.g. an allowlist check) is not recognized as sanitization unless configured in `trustedSanitizers`.

Possible false positives:

- HTTP responses from your own trusted CMS are reported (medium confidence). If the backend guarantees sanitized HTML, document an exception with a justification.
- Custom sanitizers are not trusted by default; register them in `trustedSanitizers` after review.

### NGB002 — Unsafe resource trust bypass

- Allowlist checks performed before the call (e.g. `if (ALLOWED.includes(url))`) are not yet credited; such findings keep their confidence. Use an exception with justification.
- `bypassSecurityTrustStyle()` is not covered (style injection has a much smaller impact in modern browsers).

Possible false positives:

- Embeds from a trusted provider whose ID comes from the URL (`https://www.youtube.com/embed/${id}`) are reported with reduced confidence; validate the ID format to be explicit.

### NGB003 — DOM injection sink

- An untyped receiver is only treated as an element when it is `….nativeElement`; other `any`-typed objects are skipped.
- jQuery/third-party DOM helpers (`$(el).html(v)`) are not modeled.

Possible false positives:

- Markup produced by a trusted rendering library from untrusted input (e.g. a Markdown renderer configured to escape HTML) is reported with reduced confidence because the library call is unmodeled.

### NGB004 — Dynamic code execution

- Indirect references (`const e = eval; e(x)`) are not followed.
- Execution through third-party template engines or `vm`-like libraries is not modeled.

Possible false positives:

- Expressions built only from developer-controlled configuration can still be reported when that configuration is loaded at runtime (HTTP / storage).

### NGB005 — Untrusted dynamic script loading

- Only script elements stored in a local variable or class field are tracked; elements passed through helper functions are not.
- Script tags injected via HTML strings are covered by NGB003, not this rule.

Possible false positives:

- Loader helpers that receive URLs only from your own configuration may be reported with low confidence when that configuration is loaded at runtime.

### NGB006 — Wildcard postMessage origin

- `Worker.postMessage` / `MessagePort.postMessage` are not reported (no target-origin parameter).
- Sensitivity is inferred from names and types; secrets in generically named variables (`value`, `payload`) are only detected when their data flow passes through a sensitive name.

Possible false positives:

- Broadcasting intentionally public, non-sensitive events (resize notifications, analytics pings) to an embedding page with `*` is reported only as low severity / low confidence.

### NGB007 — Missing origin validation

- Handlers registered through helper libraries or stored in variables before registration are not discovered.
- Checks performed in a different function than the read (other than a validator called in the guard condition, or a guard around the delegating call) are not recognized.
- An exact comparison against a value that is itself attacker-controlled is still treated as strict.

Possible false positives:

- Handlers that intentionally accept messages from any origin (public widget APIs) and only process inert data are reported with medium confidence; document an exception explaining why.

### NGB008 — Unverified message source

- Only peers referenced in the same class (or same file outside classes) as the handler are considered.
- The compared value is not verified to be the same peer window; any equality check on `event.source` is accepted.

Possible false positives:

- Handlers that only process messages from one origin that can host exactly one frame may not need a source check; suppress with a justification.

### NGB009 — Unvalidated message payload

- Only handlers on `window` are considered (not MessagePort/Worker/BroadcastChannel).
- Validation must be a guard on the flow (same function as the source or sink) or a call on the data path; validation stored in a flag variable is not recognized.
- The handler parameter must be typed `MessageEvent` or be inferred as one (e.g. inline `addEventListener` callbacks); `any`-typed events are not recognized as sources.

Possible false positives:

- Libraries that validate internally (e.g. a typed RPC layer) are not recognized unless the call appears as a validation guard.

### NGB010 — Overly permissive iframe

- Dynamic `[attr.sandbox]` / `[sandbox]` bindings cannot be assessed and produce an informational diagnostic instead of a finding.
- Whether the framed content is trusted is not known statically; only the shape of the configuration is assessed.
- Iframes created via `Renderer2.createElement` or third-party components are not covered.

Possible false positives:

- Trusted first-party content embedded from a dynamic but allowlisted URL is reported with low confidence when unsandboxed.

### NGB011 — Untrusted redirect

- Only guards inside the function containing the sink are considered; validation performed by a caller of a redirect helper is not seen.
- Validation inside a project function used as a guard (`if (isSafeUrl(u))`) is not analyzed; the finding is kept with low confidence.
- `u.startsWith("/") && !u.startsWith("//")` is accepted as a relative-path check; browsers also treat `/\evil.example` as protocol-relative, so also reject backslashes.

Possible false positives:

- Destinations already validated by a server-side allowlist before reaching the client.
- Weak checks such as `url.includes("example.com")` lower the confidence but are still reported because they are bypassable (`https://evil.example/?example.com`).

### NGB012 — Unsafe navigation scheme

- Only validation inside the function containing the sink is considered.
- Calls to project validation functions in a guard are not analyzed; such findings are kept with low confidence.
- Template bindings are not reported because Angular sanitizes them.

Possible false positives:

- Constant `javascript:void(0)` links are not reported; only dynamic values or dynamic `javascript:` construction are.

### NGB013 — Credential forwarding risk

- Checks performed outside the interceptor (e.g. a separate HttpClient instance via `HttpBackend`) are not seen; such interceptors may still be reported.
- Header names built dynamically are not evaluated.
- CSRF/XSRF token headers are intentionally not reported.

Possible false positives:

- Applications that only ever call a single backend may still be reported; adding an explicit destination check documents that assumption and protects future third-party calls.

### NGB014 — Insecure token storage

- Name-based evidence: credentials stored under neutral names (`localStorage.setItem("a", x)` with an untyped `x`) are not detected.
- Storage wrappers from libraries (ngx-webstorage, localForage, idb) are not modeled.
- Cookies set from JavaScript are not covered by this rule.

Possible false positives:

- Short-lived, audience-restricted tokens may be an accepted trade-off; document it with an exception and an expiry date.

### NGB015 — Sensitive payment data persistence

- Card data stored under neutral names with untyped values is not detected.
- Card data inside forms serialized wholesale (`JSON.stringify(this.form.value)`) is reported only when the form type or flow reveals card fields.
- Server-side storage and logging are out of scope.

Possible false positives:

- A field named `pan` that is not a card number (e.g. a camera pan setting) can be reported; rename it or add a scoped exception.

### NGB016 — Sensitive data logging

- Generic objects (`console.log(user)`) are reported only when their declared type exposes a sensitive property; untyped objects are not inspected.
- Custom logger services are not treated as sinks unless they delegate to a modeled API inside the scanned code.
- Telemetry objects are matched by their conventional global/import names; renamed instances are missed.

Possible false positives:

- Variables named like secrets that hold non-secret values (e.g. a boolean called `token`).
- Logging statements removed from production builds are still reported; consider removing them from source instead.

### NGB017 — Sensitive data in URLs

- URLs assembled in helper functions or with `URL`/`HttpParams` objects passed between functions are not reconstructed.
- Values are judged by names (parameter, variable, property, type) and traced names; an opaque variable like `x` carrying a token is missed.

Possible false positives:

- Protocols that require a token in the URL (e.g. signed download links, password-reset links received by e-mail) are reported; document an exception with the justification.
- Opaque payment references (`paymentToken`, `orderId`) are intentionally not treated as payment data.

### NGB018 — Hardcoded frontend secrets

- Secrets split across several literals, encoded (base64) or fetched at runtime are not detected.
- Only JSON files matching the configured globs are inspected; `.env` files are not read (they are not bundled by the Angular CLI).
- Whether a key is actually privileged cannot be verified offline; validity is never checked against the provider.

Possible false positives:

- Generated identifiers with high entropy assigned to a `secret`-named property in mocks or demo data.
- Test-mode keys are reported with low severity because they still grant access to test data.

### NGB019 — Unsafe CSP / Trusted Types policy

- Production HTTP response headers (CDN, reverse proxy, server config outside the repo) cannot be seen; their absence is reported as "not assessed", never as missing CSP.
- Structured header builders (e.g. helmet `contentSecurityPolicy.directives`) and dynamically built header strings are not evaluated; dynamic values produce an informational diagnostic.
- Report-only policies are ignored because they do not enforce anything.

Possible false positives:

- A meta CSP that is replaced by a stricter header at deploy time is still reported; prefer keeping one source of truth.

### NGB020 — Sensitive SSR transfer cache

- Whether the SSR response is actually cached or shared between users depends on deployment (CDN rules, `Cache-Control`) and cannot be determined statically.
- Cookie-authenticated requests cached by the HTTP transfer cache are not detected: whether a request carries cookies is decided at runtime.
- The body of a custom `filter` function is not evaluated.

Possible false positives:

- Pages rendered per request with `Cache-Control: private, no-store` limit exposure to the requesting user; such findings can be documented as exceptions.
- Public data with personal-sounding names (e.g. a public author `profile`) may be reported with medium confidence.

_Generated from rule metadata in `packages/rules` by `scripts/generate-limitations.mjs`._
