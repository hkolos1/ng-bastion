---
title: Installation and local setup
description: Installation status of NgBastion and how to run the scanner from a local checkout today.
---

:::caution[Not published yet]
The `ngbastion` npm package has **not been published**. Commands such as `npx ngbastion scan` show the planned interface; they do not work yet. Until the first public release, run NgBastion from a local checkout as described below.
:::

## Requirements

- Node.js **22.22.3 or newer within 22.x**, or **24.15.0 or newer within 24.x**
- pnpm 10 (via `corepack enable`)

These requirements apply to the machine running the scanner. The project being scanned only needs its sources; it is never built or executed.

## Run from a checkout

```sh
git clone <repository-url> ng-bastion   # private during development
cd ng-bastion
corepack enable
pnpm install
pnpm build
```

Then scan any Angular workspace:

```sh
node packages/cli/dist/bin.js scan /path/to/your-angular-app
# or, from the repository root:
pnpm ngbastion scan /path/to/your-angular-app
```

Check that the environment is ready:

```sh
node packages/cli/dist/bin.js doctor /path/to/your-angular-app
```

## Planned installation

Once published, the intended usage is:

```sh
npx ngbastion scan            # planned
npm install --save-dev ngbastion   # planned
```

## Dependencies of the scanned project

Installing your project's dependencies (`npm ci`) before scanning is recommended. With `node_modules` present, NgBastion identifies framework APIs through the TypeChecker. Without it, it falls back to reading import declarations and type annotations, and reports an `unresolved-imports` diagnostic so you know which mode was used.
