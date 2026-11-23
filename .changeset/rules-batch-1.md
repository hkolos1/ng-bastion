---
'@ngbastion/rules': minor
'@ngbastion/core': minor
'@ngbastion/config': minor
---

Add rules NGB021–NGB030 (disabled XSRF protection, client-controlled authorization in route guards, missing OAuth state validation, weakened OAuth/OIDC client configuration, authentication cookies set from JavaScript, untrusted HTTP request destinations / client-side path traversal, sensitive data in DOM attributes, on global objects and in navigation state, permissive referrer policy). `encodeURIComponent()` is no longer treated as an HTML sanitizer and `encodeURI()` as no sanitizer at all.
