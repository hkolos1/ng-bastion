# @ngbastion/plugin-api

## 0.2.0

### Minor Changes

- 7cb7329: Add rules NGB041–NGB050 (unsafe inline state serialization, Host header injection in SSR, insecure session cookie attributes, public production source maps, missing subresource integrity, insecure randomness, static Web Crypto IVs, weak hash algorithms, insecure dependency sources, `document.domain` relaxation). The engine models SSR request headers and Express request values as sources, no longer taints `location.origin`, and memoizes callee/type resolution. Fixes NGB002 false positives on `hasOwnProperty()` and an NGB009 crash on `Object.prototype.toString.call()`.
- 0e2924a: Add rules NGB051–NGB060: mismatched Angular sanitization contexts, unsafe custom Angular sanitizers, runtime template compilation from dynamic input, untrusted base URLs, cross-request state in SSR module scope, pass-through Trusted Types policies, missing OIDC nonce, ID tokens sent as API bearer tokens, JWTs decoded without signature verification in server code and untrusted OAuth redirect URIs. The engine now treats Express `req.body`, `req.path` and `req.cookies` as untrusted, and the plugin API gains `findWorkspaceFiles()`.

## 0.1.2

No changes in this release.

## 0.1.1

No changes in this release.
