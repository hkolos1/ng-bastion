# Security policy

## Reporting a vulnerability in NgBastion

Please **do not open a public issue** for security problems in NgBastion itself (for example a
crafted project that makes the scanner execute code, leak file contents into reports, or hide
findings).

While the repository is private, report directly to the maintainers through the private channel
you use to access the repository. Once the repository is public, use GitHub's
**private vulnerability reporting** ("Report a vulnerability" on the Security tab). No dedicated
security e-mail address exists yet; none should be assumed.

Please include the NgBastion version, Node.js version, a minimal reproduction and the impact.
We aim to acknowledge reports within 5 working days.

## Scope and trust model

- NgBastion analyzes code statically. It **never executes the scanned application**.
- `ngbastion.config.ts`/`.js` and configured **plugins are executed** as trusted code with the
  permissions of the user running the scan. They are not sandboxed. Do not run NgBastion with
  configuration or plugins from untrusted sources.
- Remote configurations and plugins are rejected; only local files and installed packages load.
- Reports contain workspace-relative paths only and redact secret-like values (NGB018).
- NgBastion sends no telemetry and makes no network requests while scanning.

## What NgBastion findings mean

A finding is evidence of a potentially dangerous pattern, not proof of exploitability. The absence
of findings does not mean an application is secure. See [docs/LIMITATIONS.md](docs/LIMITATIONS.md).
