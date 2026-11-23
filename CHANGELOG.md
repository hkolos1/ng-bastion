# Changelog

All notable changes to NgBastion are documented here. The project follows
[Semantic Versioning](https://semver.org/) and [Conventional Commits](https://www.conventionalcommits.org/);
user-visible changes are tracked with [Changesets](.changeset).

## 0.3.0 — 2026-11-23

- Expose six experimental browser-agent tools and add live NGB018 TypeScript analysis and downloadable HTML reports to the playground.

## 0.2.0 — 2026-11-23

### Reporting

- Generate a self-contained interactive HTML report with findings, code context and ordered traces.
- Track findings with versioned fingerprints and baselines, and apply status-aware security gates.
- Identify locations touched by a local Git diff and compare two saved JSON reports.

### New rules

- NGB021 Disabled XSRF protection, NGB022 Authorization decision from user-controllable state,
  NGB023 Missing OAuth state validation, NGB024 Weakened OAuth/OIDC client configuration,
  NGB025 Authentication cookie set from JavaScript, NGB026 Untrusted HTTP request destination
  (client-side path traversal), NGB027 Sensitive data in DOM attributes, NGB028 Sensitive data on
  global objects, NGB029 Sensitive data in navigation state, NGB030 Permissive referrer policy.
- NGB031 Sensitive data in CacheStorage, NGB032 Service worker caches user-specific responses
  (`ngsw-config.json` data groups and custom workers), NGB033 `window.open()` without noopener,
  NGB034 Untrusted postMessage target origin, NGB035 Untrusted dynamic method dispatch,
  NGB036 Prototype pollution, NGB037 Regular expression injection, NGB038 Sensitive form
  submission target, NGB039 JSONP request, NGB040 Plaintext network transport (HTTP, WebSocket,
  EventSource, production environment URLs).
- NGB041 Unsafe inline state serialization (SSR), NGB042 Host header injection in SSR, NGB043
  Insecure session cookie attributes, NGB044 Public production source maps, NGB045 Missing
  subresource integrity, NGB046 Insecure randomness for security values, NGB047 Static IV in Web
  Crypto encryption, NGB048 Weak hash algorithm, NGB049 Insecure dependency source, NGB050
  `document.domain` relaxation. New categories: Cryptography, Supply chain.
- NGB051 Mismatched Angular sanitization context (also `SecurityContext.NONE` and ngx-markdown
  with sanitization disabled), NGB052 Unsafe custom Angular sanitizer, NGB053 Runtime template
  compilation from dynamic input, NGB054 Untrusted base URL (`<base href>`, `APP_BASE_HREF`),
  NGB055 Cross-request state in SSR module scope, NGB056 Pass-through Trusted Types policy,
  NGB057 Missing OIDC nonce, NGB058 ID token sent as API bearer token, NGB059 JWT decoded without
  signature verification (server code), NGB060 Untrusted OAuth redirect URI. NGB055 and NGB058
  only warn in `recommended`.
- NGB061 Server-side open redirect, NGB062 Permissive Permissions-Policy, NGB063 DOM-clobberable
  global in a sensitive sink, NGB064 Untrusted CSS injection, NGB065 Broken or weak cipher, NGB066
  Sensitive data copied to the clipboard, NGB067 Sensitive data sent to analytics, NGB068 Hardcoded
  cryptographic key, NGB069 Reflected XSS in server responses, NGB070 Timing-unsafe secret
  comparison. NGB062, NGB063, NGB066 and NGB067 only warn in `recommended`.
- NGB071 Service worker scope expansion, NGB072 Service worker attaches credentials to any origin,
  NGB073 SQL injection in server code, NGB074 Service worker caches unvalidated responses, NGB075
  Untrusted worker script, NGB076 Server-side request forgery, NGB077 Path traversal in server code,
  NGB078 OS command injection, NGB079 Server-side template injection, NGB080 NoSQL injection in
  server code. NGB074 only warn in `recommended`.
- NGB081 Permissive CORS with credentials, NGB082 Spoofable client IP used for access control,
  NGB083 Cross-site WebSocket hijacking, NGB084 Session not regenerated after login, NGB085 Error
  details sent to clients, NGB086 Static password-hashing salt, NGB087 Insufficient password-hashing
  work factor, NGB088 Insufficient asymmetric key size, NGB089 Truncated authentication tag, NGB090
  Signature verification result ignored. NGB084 only warn in `recommended`.
- NGB091 Untrusted code in a privileged workflow, NGB092 Excessive workflow token permissions,
  NGB093 Third-party action not pinned to a commit, NGB094 Untrusted expression in a workflow
  script, NGB095 Untrusted artifact in a privileged workflow, NGB096 Development server exposed to
  the network, NGB097 Package manager TLS verification disabled, NGB098 TLS certificate validation
  disabled, NGB099 Untrusted module federation remote, NGB100 Untrusted import map. NGB096 only warn
  in `recommended`.
- The `recommended` preset enables them; the heuristic ones (NGB022, NGB027, NGB028, NGB030,
  NGB033, NGB037, NGB044, NGB045) only warn. Configurations without `extends` keep their explicit rule selection. To keep the previous
  behaviour on upgrade, set the new IDs to `"off"`.

### Engine

- New taint sources for SSR code: `Host` / `X-Forwarded-*` request headers (source kind
  `request-header`) and Express / Node `req.query`, `req.params`, `req.url`.
- `location.origin`, `host`, `hostname`, `protocol` and `port` are no longer tainted.
- Server request sources: `req.body`, `req.path` and `req.cookies` (Express / Node); untyped
  `(req, res)` handler parameters are recognized when Express types are not installed.
- Node `path` functions (`path.join()`, `resolve()`, `basename()`, …) propagate taint from every
  argument; `path.join()` was previously treated like `Array#join()` and lost the flow.
- Plugin API: `AnalysisContext.findWorkspaceFiles(glob)` (additive) lists workspace-level files;
  `.github` is no longer skipped when listing files. Directory listings are cached per scan.
- Callee and type resolution is memoized: scans with 50 rules are faster than 0.1.2 with 20
  (bitwarden/clients monorepo 36.8 s → 26.5 s).
- Plugin API: `SourceKind` gained `request-header`, `RuleCategory` gained `cryptography` and
  `supply-chain` (additive; exhaustive switches in plugins need a default branch).

### Fixes

- NGB002 reported every `obj.hasOwnProperty(key)` / `toString()` call on untyped receivers, and
  NGB009 crashed on `Object.prototype.toString.call(v)`: method and type names were looked up in
  plain objects, where `Object.prototype` members match.
- `encodeURIComponent()` was accepted as an HTML sanitizer and `encodeURI()` as an HTML sanitizer.
  URL encoding is not HTML escaping (`'`, `(`, `)` survive and break out of single-quoted
  attributes). Flows through them into HTML sinks (NGB001, NGB003) are now reported with one
  confidence level less; `encodeURIComponent()` still sanitizes URL contexts.

## 0.1.2 — 2026-11-23

### Fixes

- `ngbastion --version`, `--help` and `tool.version` in terminal, JSON and SARIF reports now show
  the installed version. 0.1.1 still reported 0.1.0 because the version was hardcoded; the CLI and
  `@ngbastion/core` (`ENGINE_VERSION`) now read it from their `package.json`.

## 0.1.1 — 2026-11-23

### Fixes

- Rule documentation, `ngbastion --help`, `ngbastion explain` and SARIF/JSON report links
  (`helpUri`, `informationUri`, report `$schema`) now point to https://ngbastion.web.app.
  `ngbastion.dev` was never live, so links in 0.1.0 reports led nowhere.

### Project

- Documentation site deployed to Firebase Hosting at https://ngbastion.web.app.
- Releases are published from version tags by GitHub Actions with npm Trusted Publishing,
  so packages carry npm provenance.

## 0.1.0 — 2026-11-23

### Security engine (`@ngbastion/core`)

- Type-aware, demand-driven backward taint analysis on the TypeScript Compiler API and TypeChecker.
- Interprocedural and cross-file propagation: parameters ↔ arguments (context-sensitive when
  entered from a call), return values, class fields and getters, injected services, imports.
- Angular templates parsed with `@angular/compiler` (inline and `templateUrl`); `[(ngModel)]` and
  input-event bindings modeled as user input.
- Selected RxJS (`map`, flattening operators, pass-through operators, `catchError`, `startWith`,
  `of`/`from`/`defer`, Subjects, `firstValueFrom`) and Signals (`signal`, `set`/`update`,
  `computed`, `linkedSignal`, `toSignal`, `toObservable`) support.
- Context-specific sanitizer recognition; `bypassSecurityTrust*` is never treated as a sanitizer.
- Declaration-based API identification when dependencies are not installed, including
  `inject(Service)` members; Angular entry points match their packages in typed mode.
- Analysis limits with explicit `analysis-incomplete`/`analysis-timeout` diagnostics,
  unsupported-construct and unresolved-import diagnostics.
- Stable fingerprints, inline suppressions with required justification, config exceptions with
  expiry, deduplication across projects, security gate. Reports never contain absolute paths.

### Rules (`@ngbastion/rules`)

- NGB001–NGB005 Angular XSS: trust bypass (HTML, URL/resource/script), DOM injection sinks,
  dynamic code execution, untrusted script loading.
- NGB006–NGB010 cross-window: wildcard `postMessage`, missing origin validation, unverified
  message source, unvalidated payloads, permissive iframes.
- NGB011–NGB015: untrusted redirects, unsafe navigation schemes, credential forwarding in
  interceptors, token storage, payment data persistence.
- NGB016–NGB020: sensitive logging, sensitive data in URLs, hardcoded secrets (redacted output),
  CSP / Trusted Types configuration (not assessed when unobservable), SSR transfer cache.

### CLI and configuration

- `ngbastion scan | init | explain | rules | doctor`; exit codes 0 / 1 (gate) / 2 (error).
- Terminal, versioned JSON (`report-v1` schema) and SARIF 2.1.0 (code flows, fingerprints,
  suppressions, `security-severity`) reports.
- `ngbastion.config.json` / `.ts` with `defineConfig`, presets (recommended, strict, enterprise,
  payments), shared configs via `extends`, organizational policies, exceptions, analysis limits,
  trusted sanitizers, project selection. Remote configs and plugins are rejected.
- Plugin API v1 for trusted third-party rules with version validation.

### Quality

- Unit, integration, reliability and Angular 20/21/22 compatibility suites; SARIF validated
  against the official schema; JSON validated against the published schema.
- Vulnerable showcase app demonstrating all 20 rules.
- CI templates for GitHub Actions, GitLab CI, Jenkins and Azure DevOps; internal CI on Node 22/24.

### Product

- Documentation site, landing page, rule reference, minimal fixture-based playground and original
  branding (`apps/website`, not deployed).
- The website is an Angular 22 + AnalogJS application (Vite, Tailwind CSS v4), statically
  pre-rendered for every route, with signal-based search, theme and playground; it replaced the
  initial Astro + Starlight implementation. Content is still generated from real scanner output,
  rendered through Angular's sanitizer without trust bypasses, and verified after each build.
- Scanning the website with NgBastion uncovered and fixed two scanner issues: NGB005 now ignores
  non-executable script data blocks (`type="application/ld+json"` etc.), and JSON module imports
  are treated as build-time constants.
