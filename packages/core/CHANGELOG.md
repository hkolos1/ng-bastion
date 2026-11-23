# @ngbastion/core

## 0.2.0

### Minor Changes

- c4ccb57: Add versioned semantic finding fingerprints, local baseline comparison and status-aware security gates.
- 3eff32d: Add a self-contained offline HTML security report, observed rule evaluation counts, shareable source redaction and an interactive findings explorer.
- a5ecd42: Add rules NGB021–NGB030 (disabled XSRF protection, client-controlled authorization in route guards, missing OAuth state validation, weakened OAuth/OIDC client configuration, authentication cookies set from JavaScript, untrusted HTTP request destinations / client-side path traversal, sensitive data in DOM attributes, on global objects and in navigation state, permissive referrer policy). `encodeURIComponent()` is no longer treated as an HTML sanitizer and `encodeURI()` as no sanitizer at all.
- 7cb7329: Add rules NGB041–NGB050 (unsafe inline state serialization, Host header injection in SSR, insecure session cookie attributes, public production source maps, missing subresource integrity, insecure randomness, static Web Crypto IVs, weak hash algorithms, insecure dependency sources, `document.domain` relaxation). The engine models SSR request headers and Express request values as sources, no longer taints `location.origin`, and memoizes callee/type resolution. Fixes NGB002 false positives on `hasOwnProperty()` and an NGB009 crash on `Object.prototype.toString.call()`.
- 0e2924a: Add rules NGB051–NGB060: mismatched Angular sanitization contexts, unsafe custom Angular sanitizers, runtime template compilation from dynamic input, untrusted base URLs, cross-request state in SSR module scope, pass-through Trusted Types policies, missing OIDC nonce, ID tokens sent as API bearer tokens, JWTs decoded without signature verification in server code and untrusted OAuth redirect URIs. The engine now treats Express `req.body`, `req.path` and `req.cookies` as untrusted, and the plugin API gains `findWorkspaceFiles()`.

### Patch Changes

- Updated dependencies [a5ecd42]
- Updated dependencies [2a03f59]
- Updated dependencies [7cb7329]
- Updated dependencies [0e2924a]
- Updated dependencies [ef02c2c]
- Updated dependencies [a59dcd4]
- Updated dependencies [cc13645]
- Updated dependencies [ce16391]
  - @ngbastion/config@0.2.0
  - @ngbastion/plugin-api@0.2.0

## 0.1.2

### Patch Changes

- 9715e74: `ngbastion --version`, `--help` and the `tool.version` in terminal, JSON and SARIF reports now show the
  installed package version (also `ENGINE_VERSION` in `@ngbastion/core`). 0.1.1 still reported 0.1.0.
- @ngbastion/config@0.1.2
  - @ngbastion/plugin-api@0.1.2

## 0.1.1

### Patch Changes

- @ngbastion/config@0.1.1
  - @ngbastion/plugin-api@0.1.1
