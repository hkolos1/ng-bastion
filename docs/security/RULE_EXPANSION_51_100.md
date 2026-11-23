# Rule expansion: NGB051–NGB100

Milestone: grow the built-in catalog from 50 to 100 rules. Every candidate from the proposal was
treated as a research item and checked against the existing 50 rules, real framework / runtime
behaviour, and what a local static analysis can actually observe. Candidates that duplicate an
existing rule, rest on an unprovable trust boundary or would mostly report noise were rejected and
their ID slot was given to a distinct, observable weakness.

## Initial audit (before implementation)

| Check | Result |
|---|---|
| NGB001–NGB050 present and registered | ✅ `builtinRules` lists 50 sequential IDs; `BUILTIN_RULE_IDS` matches (registry test) |
| Tested | ✅ one test file per rule (positive, safe, false-positive regression); showcase demonstrates all 50 |
| Documented | ✅ every rule has description, rationale, patterns, limitations, false positives, remediation, example; NGB021+ carry CWE + references; website pages are generated from metadata |
| Baseline tests | ✅ 59 test files, 409 tests passing (`pnpm test`, Node 24.22.0) |
| Baseline performance | 100 / 400 / 1,600 files: 321 / 461 / 1,304 ms (`node scripts/benchmark.mjs`, Apple M3 Max) |
| CI triggers | `ci.yml`: push to `main`, pull requests (build / lint / typecheck / tests, no publishing). `release.yml`: `v*` tags only (npm publish + GitHub release). Firebase deploy is manual. Nothing in this milestone touches either trigger. |

The 50-rule milestone is complete, so this milestone could start.

## Decision summary

- **Accepted as proposed (scope tightened where noted): 41**
- **Replaced: 9** (056, 061, 065, 068, 069, 070, 073, 080 — duplicates or unprovable; 062 narrowed to the header form that NGB010 does not cover)
- Rule IDs stay sequential; a replacement takes the slot of the rejected candidate, so the batch
  grouping of the proposal no longer matches the category of every rule.

| ID | Proposed | Decision | Implemented as | Category | Overlap / reason |
|---|---|---|---|---|---|
| NGB051 | Incorrect Angular sanitization context | ACCEPT | Mismatched Angular sanitization context | angular-xss | NGB001/002 trust a `sanitize()` of *any* context; this reports the context mismatch and `SecurityContext.NONE` |
| NGB052 | Unsafe custom sanitizer | ACCEPT | Unsafe custom Angular sanitizer | angular-xss | none (providers replacing `Sanitizer` / `DomSanitizer`) |
| NGB053 | Unsafe runtime template compilation | ACCEPT | Runtime template compilation from dynamic input | angular-xss | NGB004 covers `eval`/`Function`, not JIT templates |
| NGB054 | Untrusted base href | ACCEPT (absorbs NGB065 candidate) | Untrusted base URL | angular-xss | none |
| NGB055 | SSR cross-request state leakage | ACCEPT (heuristic, `warn`) | Cross-request state in SSR module scope | ssr | NGB020 covers TransferState only |
| NGB056 | Legacy OAuth implicit flow | **REPLACE** — NGB024 already reports implicit-flow configuration | Pass-through Trusted Types policy | angular-xss | NGB019 checks the CSP only, not policy bodies |
| NGB057 | Missing OIDC nonce binding | ACCEPT (narrowed to observable cases) | Missing OIDC nonce | navigation-auth | NGB023 covers `state`, NGB024 other OIDC checks |
| NGB058 | ID token used as API access token | ACCEPT | ID token sent as API bearer token | navigation-auth | none |
| NGB059 | Unverified JWT claims for privileged decisions | ACCEPT (narrowed to server code: decode without verify, `alg: none`) | JWT decoded without signature verification | ssr | NGB022 covers client-side guards; client decoding is never verification and is not reported |
| NGB060 | Untrusted OAuth redirect URI | ACCEPT | Untrusted OAuth redirect URI | navigation-auth | NGB011 covers navigation sinks, not `redirect_uri` values |
| NGB061 | Unsafe cross-origin window opener | **REPLACE** — duplicate of NGB033 | Server-side open redirect | ssr | NGB011 = browser sinks, NGB042 = Host header only |
| NGB062 | Excessive embedded permissions | ACCEPT (narrowed: NGB010 owns iframe `allow`) | Permissive Permissions-Policy | security-config | NGB010 |
| NGB063 | DOM clobbering | ACCEPT (heuristic) | DOM-clobberable global used in a sensitive sink | angular-xss | none |
| NGB064 | Untrusted CSSOM injection | ACCEPT | Untrusted CSS injection | angular-xss | NGB003 covers HTML sinks only |
| NGB065 | Untrusted base URL | **REPLACE** — merged into NGB054 | Broken or weak cipher | cryptography | NGB047 (static IV) / NGB048 (hashes) |
| NGB066 | Sensitive data to clipboard | ACCEPT (low severity, `warn`) | Sensitive data copied to the clipboard | sensitive-data | none |
| NGB067 | Sensitive data to analytics | ACCEPT | Sensitive data sent to analytics / telemetry | sensitive-data | NGB016 covers console / logger |
| NGB068 | Sensitive data to untrusted WebSocket | **REPLACE** — NGB026 (untrusted destination) + NGB040 (`ws://`) | Hardcoded cryptographic key | cryptography | NGB018 finds secret-looking literals by name / pattern, not keys passed to crypto APIs |
| NGB069 | WebRTC data channels | **REJECT** — the peer is the intended recipient; no observable trust boundary | Reflected XSS in server responses | ssr | NGB003 = DOM sinks; NGB041 = inline state serialization |
| NGB070 | Beacon API leakage | **REJECT** — NGB026 covers beacon destinations, NGB067 analytics payloads | Timing-unsafe secret comparison | ssr | none |
| NGB071 | Service worker scope expansion | ACCEPT | Service worker scope expansion | security-config | none |
| NGB072 | Service worker credential forwarding | ACCEPT (narrowed) | Service worker attaches credentials to any origin | sensitive-data | NGB013 = Angular interceptors |
| NGB073 | Sensitive IndexedDB state | **REJECT** — NGB014 / NGB015 already cover IndexedDB | SQL injection in server code | ssr | none |
| NGB074 | Service worker cache poisoning | ACCEPT (narrowed to unchecked responses) | Service worker caches unvalidated responses | security-config | NGB032 = user-specific data in caches |
| NGB075 | Untrusted worker code | ACCEPT | Untrusted worker script | angular-xss | NGB005 covers `importScripts()` / `<script>`; workers are new |
| NGB076 | SSR SSRF | ACCEPT (Node HTTP clients; browser APIs stay NGB026) | Server-side request forgery | ssr | NGB026 / NGB042 |
| NGB077 | SSR path traversal | ACCEPT | Path traversal in server code | ssr | none |
| NGB078 | SSR command injection | ACCEPT | OS command injection | ssr | none |
| NGB079 | SSR template injection | ACCEPT | Server-side template injection | ssr | none |
| NGB080 | SSR prototype pollution | **REJECT** — NGB036 traces server request sources too | NoSQL injection in server code | ssr | none |
| NGB081 | CORS origin reflection | ACCEPT | Permissive CORS with credentials | ssr | none |
| NGB082 | Spoofable proxy headers for authorization | ACCEPT | Spoofable client IP used for access control | ssr | NGB042 = Host headers in URLs |
| NGB083 | WebSocket origin enforcement | ACCEPT (narrowed) | Cross-site WebSocket hijacking | ssr | none |
| NGB084 | SSR session fixation | ACCEPT (heuristic, `warn`) | Session not regenerated after login | ssr | NGB043 = cookie attributes |
| NGB085 | SSR error details | ACCEPT | Error details sent to clients | ssr | NGB016 = logging |
| NGB086 | Predictable KDF salt | ACCEPT | Static password-hashing salt | cryptography | NGB047 = IVs |
| NGB087 | Insufficient KDF work factor | ACCEPT | Insufficient password-hashing work factor | cryptography | none |
| NGB088 | Weak asymmetric keys | ACCEPT | Insufficient asymmetric key size | cryptography | none |
| NGB089 | Short AEAD tag | ACCEPT | Truncated authentication tag | cryptography | none |
| NGB090 | Ignored signature verification | ACCEPT | Signature verification result ignored | cryptography | none |
| NGB091 | `pull_request_target` | ACCEPT | Untrusted code in a privileged workflow | supply-chain | none |
| NGB092 | Excessive token permissions | ACCEPT | Excessive workflow token permissions | supply-chain | none |
| NGB093 | Mutable third-party actions | ACCEPT | Third-party action not pinned to a commit | supply-chain | NGB049 = npm dependencies |
| NGB094 | CI expression injection | ACCEPT | Untrusted expression in a workflow script | supply-chain | none |
| NGB095 | Untrusted artifact promotion | ACCEPT (narrowed to `workflow_run`) | Untrusted artifact in a privileged workflow | supply-chain | NGB091 = checkout of PR code |
| NGB096 | Exposed dev server | ACCEPT | Development server exposed to the network | security-config | none |
| NGB097 | npm TLS verification disabled | ACCEPT | Package manager TLS verification disabled | supply-chain | NGB049 = specifiers, not transport settings |
| NGB098 | Node TLS validation disabled | ACCEPT | TLS certificate validation disabled | security-config | NGB040 = plaintext URLs |
| NGB099 | Untrusted module federation remote | ACCEPT | Untrusted module federation remote | supply-chain | NGB005 = `<script>` / `import()` |
| NGB100 | Unsafe import map remapping | ACCEPT (narrowed) | Untrusted import map | supply-chain | NGB045 = SRI |

Per-rule threat model, evidence requirements, confidence and false-positive notes are in the rule
metadata (`ngbastion explain NGBxxx`, website rule pages) and summarised below as the batches land.

## Engine changes for this milestone

- Server request sources: `req.body` (user input, high trust), `req.path` (URL) and `req.cookies`
  (cookie, medium) on Express / Node request objects. Untyped `(req, res)` handler parameters (types
  not installed) are recognized as Node requests by their conventional names.
- `findWorkspaceFiles(glob)` on the analysis context (additive plugin-API member) for
  workspace-level configuration, and `.github` is no longer skipped when listing files, so CI
  workflows can be analyzed. Directory listings are cached per scan instead of re-walked per call.
- `shared/server.ts`: module-call matching for `import`, namespace / default imports and
  `require()` bindings, and Express / Node request / response recognition.

## Status

| Batch | Rules | State |
|---|---|---|
| A | NGB051–NGB060 | ✅ implemented, tested (positive / safe / false-positive regression), in the showcase |
| B | NGB061–NGB070 | ✅ implemented, tested (positive / safe / false-positive regression), in the showcase |
| C | NGB071–NGB080 | ✅ implemented, tested (positive / safe / false-positive regression), in the showcase |
| D | NGB081–NGB090 | ✅ implemented, tested (positive / safe / false-positive regression), in the showcase |
