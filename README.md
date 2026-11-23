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
- **100 security rules** (below), **terminal / HTML / JSON / SARIF 2.1.0** reports, **CI security gates**.
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
ngbastion scan --format html --output security-report.html
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

Open the HTML file directly in a browser to explore severity, confidence, source-to-sink evidence and remediation. HTML requires an output path. Add `--redact-source` to withhold snippets, finding messages, trace descriptions and diagnostic messages before sharing. Paths and rule metadata remain visible. Use the browser’s Print command to export the current filtered selection, including all its pages.

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
| NGB021 | Disabled XSRF protection | High |
| NGB022 | Authorization decision from user-controllable state | Medium |
| NGB023 | Missing OAuth state validation | High |
| NGB024 | Weakened OAuth/OIDC client configuration | High |
| NGB025 | Authentication cookie set from JavaScript | High |
| NGB026 | Untrusted HTTP request destination | High |
| NGB027 | Sensitive data in DOM attributes | Medium |
| NGB028 | Sensitive data on global objects | Medium |
| NGB029 | Sensitive data in navigation state | High |
| NGB030 | Permissive referrer policy | Medium |
| NGB031 | Sensitive data in CacheStorage | Medium |
| NGB032 | Service worker caches user-specific responses | Medium |
| NGB033 | window.open() without noopener | Low |
| NGB034 | Untrusted postMessage target origin | High |
| NGB035 | Untrusted dynamic method dispatch | High |
| NGB036 | Prototype pollution | High |
| NGB037 | Regular expression injection | Medium |
| NGB038 | Sensitive form submission target | High |
| NGB039 | JSONP request | Medium |
| NGB040 | Plaintext network transport | Medium |
| NGB041 | Unsafe inline state serialization | High |
| NGB042 | Host header injection in SSR | High |
| NGB043 | Insecure session cookie attributes | High |
| NGB044 | Public production source maps | Low |
| NGB045 | Missing subresource integrity | Medium |
| NGB046 | Insecure randomness for security values | High |
| NGB047 | Static IV in Web Crypto encryption | High |
| NGB048 | Weak hash algorithm | Medium |
| NGB049 | Insecure dependency source | Medium |
| NGB050 | document.domain relaxation | Medium |
| NGB051 | Mismatched Angular sanitization context | High |
| NGB052 | Unsafe custom Angular sanitizer | High |
| NGB053 | Runtime template compilation from dynamic input | High |
| NGB054 | Untrusted base URL | High |
| NGB055 | Cross-request state in SSR module scope | Medium |
| NGB056 | Pass-through Trusted Types policy | High |
| NGB057 | Missing OIDC nonce | Medium |
| NGB058 | ID token sent as API bearer token | Medium |
| NGB059 | JWT decoded without signature verification | High |
| NGB060 | Untrusted OAuth redirect URI | High |
| NGB061 | Server-side open redirect | Medium |
| NGB062 | Permissive Permissions-Policy | Low |
| NGB063 | DOM-clobberable global in a sensitive sink | Medium |
| NGB064 | Untrusted CSS injection | Medium |
| NGB065 | Broken or weak cipher | High |
| NGB066 | Sensitive data copied to the clipboard | Low |
| NGB067 | Sensitive data sent to analytics | Medium |
| NGB068 | Hardcoded cryptographic key | High |
| NGB069 | Reflected XSS in server responses | High |
| NGB070 | Timing-unsafe secret comparison | Medium |
| NGB071 | Service worker scope expansion | Medium |
| NGB072 | Service worker attaches credentials to any origin | High |
| NGB073 | SQL injection in server code | Critical |
| NGB074 | Service worker caches unvalidated responses | Medium |
| NGB075 | Untrusted worker script | High |
| NGB076 | Server-side request forgery | High |
| NGB077 | Path traversal in server code | High |
| NGB078 | OS command injection | Critical |
| NGB079 | Server-side template injection | Critical |
| NGB080 | NoSQL injection in server code | High |
| NGB081 | Permissive CORS with credentials | High |
| NGB082 | Spoofable client IP used for access control | High |
| NGB083 | Cross-site WebSocket hijacking | High |
| NGB084 | Session not regenerated after login | Medium |
| NGB085 | Error details sent to clients | Medium |
| NGB086 | Static password-hashing salt | Medium |
| NGB087 | Insufficient password-hashing work factor | Medium |
| NGB088 | Insufficient asymmetric key size | Medium |
| NGB089 | Truncated authentication tag | Medium |
| NGB090 | Signature verification result ignored | High |
| NGB091 | Untrusted code in a privileged workflow | Critical |
| NGB092 | Excessive workflow token permissions | Medium |
| NGB093 | Third-party action not pinned to a commit | Medium |
| NGB094 | Untrusted expression in a workflow script | High |
| NGB095 | Untrusted artifact in a privileged workflow | High |
| NGB096 | Development server exposed to the network | Low |
| NGB097 | Package manager TLS verification disabled | High |
| NGB098 | TLS certificate validation disabled | High |
| NGB099 | Untrusted module federation remote | High |
| NGB100 | Untrusted import map | High |

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

### Finding identity and baselines

```sh
ngbastion scan --create-baseline
ngbastion scan --baseline .ngbastion-baseline.json --fail-on high --fail-on-status new
ngbastion scan --baseline .ngbastion-baseline.json --update-baseline
```

Creation uses the workspace root by default. An explicit baseline path is relative to the invoking directory. Ordinary comparison is read-only. Creation refuses to overwrite. Updates require a valid prior baseline and refuse unverified disappearances. The writer uses a same-directory temporary file and a short-lived exclusive lock. After an interrupted write, verify that no writer is active before removing a stale `.lock`.

The versioned [baseline schema](packages/cli/schema/baseline-v1.json) stores SHA-256 fingerprints, relative paths, rule IDs, severity, confidence and coverage metadata. V2 hashes rule ID, normalized file path, significant operation tokens, enclosing named scopes and available trace endpoint symbols or descriptions. Identical operations in the same scope receive a source-order occurrence number. Renames, substantial refactors and inserting an identical operation before another can change identity. Location-only rules fall back to tokenizing the reported line. V1 exception matching and SARIF fingerprints remain supported. JSON v1 preserves its finding objects and adds identities, a comparison snapshot and optional comparison results under `scan`.

New and resolved describe observed differences across comparable scans. Missing coverage, changed configuration or scanner version, hidden findings and analysis diagnostics can make a difference uncertain. A resolved result means the scanner no longer reports the operation in comparable coverage. An ordinary scan still shows every active finding. With `--fail-on-status new`, uncertain current findings also count toward the gate. The severity order is info, low, medium, high, critical. Confidence is low, medium, high. Both thresholds are inclusive. Use `--fail-on-confidence high` to narrow only the gate. Policies with mandatory rules or a severity ceiling reject gate narrowing. Exit codes remain 0, 1 and 2.

### Local Git changes and report comparison

```sh
ngbastion scan apps/shop --diff origin/main --format html -o changes.html
ngbastion report compare previous.json current.json
ngbastion report compare previous.json current.json --format json -o comparison.json
```

The revision must already exist locally. Git compares its tree to the current working tree, including staged, unstaged and untracked non-ignored paths. The scanner keeps its whole-project context. A finding is associated with a changed line if the finding region or a recorded trace region intersects a current-side hunk. Other findings in changed files are labeled changed-file. Deleted files carry no current-side lines. Submodule contents are excluded. Unstaged moves can appear as a deletion and an untracked addition. Diff association leaves the gate and baseline status intact.

Report comparison reads two completed JSON v1 reports containing the reporting snapshot. It lists current finding statuses, comparable disappearances, uncertain disappearances, severity and confidence changes, and observed file and rule coverage changes. Older reports without identity and coverage data require a fresh scan. Successful comparisons exit 0 regardless of differences. Invalid inputs exit 2.
