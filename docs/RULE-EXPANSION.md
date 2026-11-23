# Rule expansion: NGB021–NGB050

Milestone: grow the built-in catalog from 20 to 50 rules with distinct, tested detections.
NGB051–NGB100 are out of scope until this set has been stabilized and its findings reviewed on
real projects.

## Audit of NGB001–NGB020

| Area | Covered by | Notes |
|---|---|---|
| HTML / resource trust bypass | NGB001, NGB002 | data flow |
| Raw DOM HTML sinks (incl. `srcdoc`) | NGB003 | data flow |
| `eval` / `Function` / string timers | NGB004 | data flow |
| Script element / dynamic `import()` | NGB005 | data flow + pattern |
| postMessage `'*'`, origin/source/payload validation | NGB006–NGB009 | NGB007 already reports **weak** origin checks (`startsWith`, `includes`, unanchored regex) |
| iframe sandbox / permissions | NGB010 | |
| Redirects, dangerous schemes | NGB011, NGB012 | |
| Interceptor credential forwarding | NGB013 | interceptors only |
| Token / card data in Web Storage, IndexedDB, card data in cookies | NGB014, NGB015 | auth cookies written by JS were not covered |
| Logging, URLs, hardcoded secrets | NGB016–NGB018 | |
| CSP / Trusted Types | NGB019 | |
| SSR TransferState / HTTP transfer cache | NGB020 | |

### Engine finding: URL encoding treated as HTML sanitization

`encodeURIComponent()` was registered as a sanitizer for the HTML context and `encodeURI()` as an
HTML sanitizer. Neither escapes HTML: `encodeURIComponent()` leaves `'`, `(`, `)`, `!`, `*` intact,
enough to break out of a single-quoted attribute in an HTML string (the tokenizer starts a new
attribute even without whitespace), and `encodeURI()` also keeps `:` and `/`. Fixed: 
`encodeURIComponent()` now only sanitizes URL / resource-URL contexts; `encodeURI()` sanitizes
nothing. Flows through either into an HTML sink are reported with one approximation (one confidence
level lower). This can add NGB001/NGB003 findings on upgrade; they are real.

## Candidate evaluation

The proposal listed 30 candidates. Each was kept, renamed (scope tightened so it reports something
that is observable in the repository), merged, or replaced.

| ID | Proposed | Decision | Implemented as |
|---|---|---|---|
| NGB021 | Disabled XSRF protection | kept | Disabled XSRF protection |
| NGB022 | Client-side-only authorization | **narrowed**: server-side checks are not observable, so "reliance" cannot be shown. Reports route guards whose decision comes from user-controllable state (URL, Web Storage, cookies) | Authorization decision from user-controllable state |
| NGB023 | OAuth/OIDC state validation | kept, limited to hand-written callbacks that exchange `code` | Missing OAuth state validation |
| NGB024 | Insecure PKCE configuration | **widened** to explicit weakening options of `angular-oauth2-oidc` / `angular-auth-oidc-client` (plain PKCE, PKCE disabled, implicit flow, issuer/at_hash checks off, `requireHttps: false`) | Weakened OAuth/OIDC client configuration |
| NGB025 | Auth cookies created by JS | kept (NGB014 covers storage APIs only) | Authentication cookie set from JavaScript |
| NGB026 | Credentialed cross-origin requests | **replaced**: with `credentials: 'include'` the browser sends cookies of the *destination*, so a credentialed request to an untrusted host leaks nothing by itself; NGB013 covers interceptors. Replaced by the real problem class: untrusted data choosing the request destination or path (client-side request forgery / client-side path traversal), with higher severity when credentials or an auth header travel with it | Untrusted HTTP request destination |
| NGB027 | Sensitive values in DOM attributes | kept | Sensitive data in DOM attributes |
| NGB028 | Secrets on global objects | kept | Sensitive data on global objects |
| NGB029 | `window.name` / navigation state | kept (`window.name`, `history.pushState/replaceState`) | Sensitive data in navigation state |
| NGB030 | Referrer leakage | **narrowed**: tokens in URLs are NGB017. This rule reports permissive referrer policies (`unsafe-url`, `no-referrer-when-downgrade`, `origin-when-cross-origin` …) in index.html, templates, fetch options, hosting configs and server code | Permissive referrer policy |
| NGB031 | Sensitive responses in CacheStorage | kept | Sensitive data in CacheStorage |
| NGB032 | Unsafe custom service-worker caching | kept; also Angular `ngsw-config.json` `dataGroups` for user-specific APIs | Service worker caches user-specific responses |
| NGB033 | Sensitive bodies to external destinations | **merged into NGB026** (sensitive body raises its severity); "unexpected destination" is not decidable without an allowlist. Replaced by reverse tabnabbing via `window.open()` | `window.open()` without noopener |
| NGB034 | Weak origin allowlisting | **duplicate of NGB007** (already reports substring/unanchored checks). Replaced by attacker-controlled `postMessage` target origins (echoing `event.origin`, origins from URL/referrer), which NGB006 does not cover (it only sees literal `'*'`) | Untrusted postMessage target origin |
| NGB035 | Message data controlling command dispatch | kept, generalized to any untrusted source selecting a function (`handlers[data.cmd]()`) | Untrusted dynamic method dispatch |
| NGB036 | BroadcastChannel without trust boundary | **replaced**: BroadcastChannel is same-origin only; its receivers are the application's own code, so a finding would be noise. Replaced by prototype pollution | Prototype pollution |
| NGB037 | Untrusted HTML in iframe `srcdoc` | **duplicate of NGB003** (`srcdoc` sink) and NGB001 (`[srcdoc]` binding needs a bypass). Replaced by regular expressions built from untrusted input | Regular expression injection |
| NGB038 | Sensitive forms to untrusted destinations | kept: forms with password / card fields posting to `http:`, external or dynamic actions | Sensitive form submission target |
| NGB039 | Insecure WebSocket | **merged into NGB040** (same weakness, CWE-319). Replaced by Angular JSONP | JSONP request |
| NGB040 | Plaintext HTTP requests | kept, covers `http://` HTTP, `ws://` WebSocket and EventSource | Plaintext network transport |
| NGB041 | SSR data in HTML outside TransferState | kept, focused on serializing state into inline `<script>`, where `JSON.stringify` does not escape `</script>` (XSS) and personal data becomes public HTML | Unsafe inline state serialization |
| NGB042 | Host header influencing SSR URLs | kept (new `request-header` taint source) | Host header injection in SSR |
| NGB043 | Insecure SSR session-cookie attributes | kept | Insecure session cookie attributes |
| NGB044 | Production source maps | kept | Public production source maps |
| NGB045 | Third-party script without SRI | kept | Missing subresource integrity |
| NGB046 | Insecure randomness | kept | Insecure randomness for security values |
| NGB047 | Static IV in Web Crypto | kept | Static IV in Web Crypto encryption |
| NGB048 | Weak hash algorithms | kept | Weak hash algorithm |
| NGB049 | Mutable dependency sources | kept | Insecure dependency source |
| NGB050 | `document.domain` | kept | `document.domain` relaxation |

## Defaults

- Rules backed by data flow or unambiguous configuration are `error` in `recommended`.
- Heuristic or context-dependent rules are `warn` in `recommended` (they never fail the default
  gate): NGB022, NGB027, NGB028, NGB030, NGB033, NGB037, NGB044, NGB045.
- The `enterprise` and `payments` mandatory-rule lists are unchanged in this milestone; promote
  rules into them only after their real-world false-positive rate is known.
- Configurations without `extends` keep their explicit rule selection: new rules stay off for them.
