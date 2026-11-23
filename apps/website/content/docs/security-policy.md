---
title: Security policy
description: How to report vulnerabilities in NgBastion responsibly.
---

Please do not report vulnerabilities in NgBastion through public issues.

Use GitHub's **private vulnerability reporting** ("Report a vulnerability" on the [repository's Security tab](https://github.com/hkolos1/ng-bastion/security)). No separate security e-mail address exists.

Relevant reports include code execution or file access triggered by scanning a malicious project, secrets leaking into reports, and bypasses of documented configuration or policy guarantees. False negatives in rules are welcome as regular issues with a minimal reproduction.

Note that `ngbastion.config.ts` files and configured plugins execute code by design; this is documented behaviour, not a vulnerability.

See `SECURITY.md` in the repository for supported versions and the disclosure process.
