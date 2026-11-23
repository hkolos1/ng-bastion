---
'@ngbastion/rules': minor
'@ngbastion/core': minor
'@ngbastion/config': minor
'@ngbastion/plugin-api': minor
---

Add rules NGB051–NGB060: mismatched Angular sanitization contexts, unsafe custom Angular sanitizers, runtime template compilation from dynamic input, untrusted base URLs, cross-request state in SSR module scope, pass-through Trusted Types policies, missing OIDC nonce, ID tokens sent as API bearer tokens, JWTs decoded without signature verification in server code and untrusted OAuth redirect URIs. The engine now treats Express `req.body`, `req.path` and `req.cookies` as untrusted, and the plugin API gains `findWorkspaceFiles()`.
