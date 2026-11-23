# Changelog

All notable changes to NgBastion are documented here. The project follows
[Semantic Versioning](https://semver.org/) and [Conventional Commits](https://www.conventionalcommits.org/);
user-visible changes are tracked with [Changesets](.changeset).

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
