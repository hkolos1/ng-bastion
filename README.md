<p align="center">
  <img src="assets/brand/logo-full.svg" alt="NgBastion" width="320">
</p>

<h3 align="center">Your Angular security stronghold.</h3>

<p align="center">
  An Angular-aware, local-first security scanner that traces untrusted data through your
  TypeScript, templates, services, RxJS pipelines and signals — and explains every finding.
</p>

<p align="center">
  <a href="https://www.npmjs.com/package/ngbastion"><img src="https://img.shields.io/npm/v/ngbastion?color=cb3837&logo=npm" alt="npm version"></a>
  <a href="https://github.com/hkolos1/ng-bastion/actions/workflows/ci.yml"><img src="https://github.com/hkolos1/ng-bastion/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="LICENSE"><img src="https://img.shields.io/npm/l/ngbastion" alt="MIT license"></a>
</p>

---

## Why NgBastion

Angular already protects you from most XSS: template bindings are sanitized by default. The risky
code is the code that steps *around* those protections — `bypassSecurityTrustHtml()`, raw DOM
writes through `ElementRef`, `postMessage` handlers without origin checks, interceptors that leak
bearer tokens, card data in `localStorage`. Generic JavaScript linters see function names;
NgBastion follows the data.

```console
$ ngbastion scan
HIGH     NGB001  Unsafe HTML trust bypass  confidence: high · dataflow
  src/app/xss/profile-card.component.ts:14:28
  Untrusted data (URL query parameter 'bio' (ActivatedRoute)) is marked as trusted HTML
  with bypassSecurityTrustHtml(); Angular will not sanitize it.
  │ readonly bio: SafeHtml = this.sanitizer.bypassSecurityTrustHtml(this.bios.previewBio());
  Trace:
    1. source       src/app/xss/bio.service.ts:10:17  URL query parameter 'bio'
                    (ActivatedRoute)
    2. assignment   src/app/xss/bio.service.ts:10:11  assigned to 'bio'
    3. transform    src/app/xss/bio.service.ts:11:12  interpolated into a template literal
    4. return       src/app/xss/profile-card.component.ts:14:67  returned from previewBio()
    5. sink         src/app/xss/profile-card.component.ts:14:28  bypassSecurityTrustHtml()
                    disables Angular HTML sanitization
  Fix: Bind untrusted HTML with `[innerHTML]` directly and let Angular sanitize it,
       or sanitize explicitly … → ngbastion explain NGB001
```

*Real output of `ngbastion scan` on [`examples/vulnerable-showcase`](examples/vulnerable-showcase), an intentionally vulnerable app (long lines wrapped to fit).*

## Key capabilities

- **Type-aware data-flow engine** built on the TypeScript Compiler API and TypeChecker: assignments,
  parameters ↔ arguments, return values, class fields, injected services, cross-file imports.
- **Angular-aware**: inline/external templates (via `@angular/compiler`), `[(ngModel)]` and input
  event bindings as user input, `ActivatedRoute`, `HttpClient`, `DomSanitizer`, `Renderer2`,
  `ElementRef`, `@HostListener`, `TransferState`, HTTP interceptors. Sanitized `[innerHTML]`
  bindings are **not** reported.
- **Selected RxJS and signals support**: `map`, `switchMap`/`mergeMap`/`concatMap`/`exhaustMap`,
  `tap`/`filter`/`take`…, `catchError`, `startWith`, `of`/`from`/`defer`, Subjects, `signal`,
  `computed`, `linkedSignal`, `toSignal`, `toObservable`, `firstValueFrom`.
- **Source-to-sink traces** with file, line, symbol and transformation for every data-flow finding.
- **Severity and confidence are separate**; heuristic findings are labelled as such.
- **Bounded analysis**: depth, call-site, file-hop, node and time limits; when one is hit you get an
  explicit `analysis-incomplete` diagnostic instead of silent gaps.
- **20 security rules** (below), **terminal / JSON / SARIF 2.1.0** reports, **CI security gates**.
- **Enterprise configuration**: presets, shared configs, organizational policies with mandatory
  rules, expiring exceptions, inline suppressions with required justification.
- **Local-first**: no telemetry, no uploads, no network access during scans.

## Compatibility

| | Supported |
|---|---|
| Scanned projects | Angular **20, 21, 22** (verified by compatibility fixtures with installed framework packages). The app is never built or executed. |
| Scanner runtime | Node.js **22.22.3+** (22.x) and **24.15.0+** (24.x) |
| Without `node_modules` | Works: framework APIs are identified from import declarations; a diagnostic tells you type information was limited. |

## Getting started

Run it in your Angular workspace, no install needed:

```bash
npx ngbastion scan
```

Or add it as a dev dependency:

```bash
npm install --save-dev ngbastion
npx ngbastion scan
```

### CLI

```bash
ngbastion scan [dir]                       # terminal report, gate on high+
ngbastion scan --format json --output ngbastion.json
ngbastion scan --format sarif --output results.sarif
ngbastion scan --fail-on critical          # or: high | medium | low | info | none
ngbastion scan --min-confidence low        # show low-confidence (heuristic) findings
ngbastion scan --project admin-app         # pick angular.json projects (repeatable)
ngbastion init --format ts --preset strict # create ngbastion.config.ts
ngbastion explain NGB001                   # rule documentation in the terminal
ngbastion rules --category angular-xss
ngbastion doctor                           # read-only environment check
```

Exit codes: **0** success · **1** security gate failed · **2** configuration or execution error.

### Configuration

```ts
// ngbastion.config.ts — loading a TypeScript config executes it.
import { defineConfig } from 'ngbastion/config';

export default defineConfig({
  extends: ['recommended'],          // recommended | strict | enterprise | payments | ./shared.json | @acme/ngbastion-config
  rules: {
    NGB001: 'error',
    NGB014: { level: 'warn', severity: 'medium' },
    NGB020: 'off',
  },
  exclude: ['**/*.spec.ts', 'dist/**'],
  failOn: 'high',
  exceptions: [
    { rule: 'NGB003', files: ['src/app/legacy/**'], justification: 'Admin-only legacy widget, tracked in SEC-142', expires: '2027-03-31' },
  ],
});
```

`ngbastion.config.json` uses the same schema. See the [configuration docs](apps/website/src/content/docs/docs) for
policies, exceptions, inline suppressions, analysis limits and trusted sanitizers.

## Security rules

| ID | Rule | Default severity |
|---|---|---|
| NGB001 | Unsafe HTML trust bypass | High |
| NGB002 | Unsafe resource trust bypass | High |
| NGB003 | DOM injection sink | High |
| NGB004 | Dynamic code execution | Critical |
| NGB005 | Untrusted dynamic script loading | High |
| NGB006 | Wildcard postMessage origin | High |
| NGB007 | Missing origin validation | High |
| NGB008 | Unverified message source | Medium |
| NGB009 | Unvalidated message payload | High |
| NGB010 | Overly permissive iframe | Medium |
| NGB011 | Untrusted redirect | High |
| NGB012 | Unsafe navigation scheme | High |
| NGB013 | Credential forwarding risk | High |
| NGB014 | Insecure token storage | High |
| NGB015 | Sensitive payment data persistence | Critical |
| NGB016 | Sensitive data logging | High |
| NGB017 | Sensitive data in URLs | High |
| NGB018 | Hardcoded frontend secrets | High |
| NGB019 | Unsafe CSP / Trusted Types policy | Medium |
| NGB020 | Sensitive SSR transfer cache | High |

Every rule documents its detected patterns, limitations, false-positive considerations and
remediation: `ngbastion explain <ID>` or the generated rule pages of the documentation site.

## Documentation

The documentation site (`apps/website`, an Angular 22 + AnalogJS application pre-rendered to static
HTML, deployed at **[ngbastion.web.app](https://ngbastion.web.app)**)
covers getting started, the CLI reference, all rules, configuration, the security engine,
the plugin API and CI/CD. Repository docs:

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — packages and engine design
- [docs/LIMITATIONS.md](docs/LIMITATIONS.md) — what NgBastion does not see
- [docs/PERFORMANCE.md](docs/PERFORMANCE.md) — measured scan times
- [docs/ROADMAP.md](docs/ROADMAP.md) — progress and deferred work
- [ci-templates/](ci-templates) — GitHub Actions, GitLab CI, Jenkins, Azure DevOps

## Security limitations

NgBastion is a static analyzer with a deliberately bounded model. It does **not** replace
penetration testing, server-side authorization, browser security controls or a professional
assessment. **No findings does not mean the application is secure** — only that none of the
modeled patterns and data flows were found. Read [docs/LIMITATIONS.md](docs/LIMITATIONS.md).

Plugins and TypeScript config files are executed as trusted code; NgBastion does not sandbox them.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Security issues: [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE). Third-party notices: [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
