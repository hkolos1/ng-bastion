---
'@ngbastion/rules': minor
'@ngbastion/core': minor
'@ngbastion/config': minor
'@ngbastion/plugin-api': minor
---

Add rules NGB041–NGB050 (unsafe inline state serialization, Host header injection in SSR, insecure session cookie attributes, public production source maps, missing subresource integrity, insecure randomness, static Web Crypto IVs, weak hash algorithms, insecure dependency sources, `document.domain` relaxation). The engine models SSR request headers and Express request values as sources, no longer taints `location.origin`, and memoizes callee/type resolution. Fixes NGB002 false positives on `hasOwnProperty()` and an NGB009 crash on `Object.prototype.toString.call()`.
