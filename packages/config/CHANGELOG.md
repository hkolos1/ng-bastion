# @ngbastion/config

## 0.2.0

### Minor Changes

- a5ecd42: Add rules NGB021–NGB030 (disabled XSRF protection, client-controlled authorization in route guards, missing OAuth state validation, weakened OAuth/OIDC client configuration, authentication cookies set from JavaScript, untrusted HTTP request destinations / client-side path traversal, sensitive data in DOM attributes, on global objects and in navigation state, permissive referrer policy). `encodeURIComponent()` is no longer treated as an HTML sanitizer and `encodeURI()` as no sanitizer at all.
- 2a03f59: Add rules NGB031–NGB040: sensitive data in CacheStorage, service worker caching of user-specific responses (`ngsw-config.json` and custom workers), `window.open()` without noopener, untrusted postMessage target origins, untrusted dynamic method dispatch, prototype pollution, regular expression injection, sensitive form submission targets, JSONP requests and plaintext network transport.
- 7cb7329: Add rules NGB041–NGB050 (unsafe inline state serialization, Host header injection in SSR, insecure session cookie attributes, public production source maps, missing subresource integrity, insecure randomness, static Web Crypto IVs, weak hash algorithms, insecure dependency sources, `document.domain` relaxation). The engine models SSR request headers and Express request values as sources, no longer taints `location.origin`, and memoizes callee/type resolution. Fixes NGB002 false positives on `hasOwnProperty()` and an NGB009 crash on `Object.prototype.toString.call()`.
- 0e2924a: Add rules NGB051–NGB060: mismatched Angular sanitization contexts, unsafe custom Angular sanitizers, runtime template compilation from dynamic input, untrusted base URLs, cross-request state in SSR module scope, pass-through Trusted Types policies, missing OIDC nonce, ID tokens sent as API bearer tokens, JWTs decoded without signature verification in server code and untrusted OAuth redirect URIs. The engine now treats Express `req.body`, `req.path` and `req.cookies` as untrusted, and the plugin API gains `findWorkspaceFiles()`.
- ef02c2c: Add rules NGB061–NGB070: server-side open redirect, permissive Permissions-Policy, DOM-clobberable global in a sensitive sink, untrusted CSS injection, broken or weak cipher, sensitive data copied to the clipboard, sensitive data sent to analytics, hardcoded cryptographic key, reflected XSS in server responses, timing-unsafe secret comparison.
- a59dcd4: Add rules NGB071–NGB080: service worker scope expansion, service worker attaches credentials to any origin, SQL injection in server code, service worker caches unvalidated responses, untrusted worker script, server-side request forgery, path traversal in server code, OS command injection, server-side template injection, noSQL injection in server code.
- cc13645: Add rules NGB081–NGB090: permissive CORS with credentials, spoofable client IP used for access control, cross-site WebSocket hijacking, session not regenerated after login, error details sent to clients, static password-hashing salt, insufficient password-hashing work factor, insufficient asymmetric key size, truncated authentication tag, signature verification result ignored.
- ce16391: Add rules NGB091–NGB100: untrusted code in a privileged workflow, excessive workflow token permissions, third-party action not pinned to a commit, untrusted expression in a workflow script, untrusted artifact in a privileged workflow, development server exposed to the network, package manager TLS verification disabled, TLS certificate validation disabled, untrusted module federation remote, untrusted import map.

### Patch Changes

- Updated dependencies [7cb7329]
- Updated dependencies [0e2924a]
  - @ngbastion/plugin-api@0.2.0

## 0.1.2

### Patch Changes

- @ngbastion/plugin-api@0.1.2

## 0.1.1

### Patch Changes

- @ngbastion/plugin-api@0.1.1
