---
title: Security policy
description: How to report vulnerabilities in NgBastion responsibly.
---

Please do not report vulnerabilities in NgBastion through public issues.

While the repository is private during development, vulnerabilities can be reported to the maintainers directly. Once the repository is public, use GitHub's **private vulnerability reporting** ("Report a vulnerability" on the repository's Security tab). No separate security e-mail address exists.

Relevant reports include code execution or file access triggered by scanning a malicious project, secrets leaking into reports, and bypasses of documented configuration or policy guarantees. False negatives in rules are welcome as regular issues with a minimal reproduction.

Note that `ngbastion.config.ts` files and configured plugins execute code by design; this is documented behaviour, not a vulnerability.

See `SECURITY.md` in the repository for supported versions and the disclosure process.
