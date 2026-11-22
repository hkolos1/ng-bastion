---
title: Contributing
description: How to develop NgBastion, run tests and contribute security rules.
---

The repository is a pnpm + Turborepo monorepo: `packages/core` (engine), `packages/rules`, `packages/cli`, `packages/config`, `packages/plugin-api`, `apps/website`, plus `examples/` and `tests/`.

```sh
corepack enable
pnpm install
pnpm build
pnpm lint && pnpm typecheck && pnpm test
```

## Contributing a rule

A rule is accepted when it has:

- complete `docs` metadata: description, rationale, exact supported patterns, limitations, false-positive considerations, remediation and examples;
- tests for positive cases, negative cases, a safe equivalent, false-positive regressions, cross-file flows where relevant, and severity/confidence assertions;
- precise detection: prefer type-aware symbol matching and traced data flow over name matching, and lower confidence when evidence is weaker.

Use Conventional Commits (`feat(rules): …`, `fix(core): …`). See `CONTRIBUTING.md` in the repository for the full guide.
