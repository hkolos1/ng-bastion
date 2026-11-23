---
title: Installation
description: Run NgBastion with npx or install it as a dev dependency of your Angular workspace.
---

## Requirements

- Node.js **22.22.3 or newer within 22.x**, or **24.15.0 or newer within 24.x**

These requirements apply to the machine running the scanner. The project being scanned only needs its sources; it is never built or executed.

## Run without installing

From the root of your Angular workspace:

```sh
npx ngbastion scan
```

Check that the environment is ready:

```sh
npx ngbastion doctor
```

## Install as a dev dependency

Pinning the version in `package.json` keeps local runs and CI on the same rules:

```sh
npm install --save-dev ngbastion
npx ngbastion init --preset recommended
npx ngbastion scan
```

pnpm and Yarn work the same way (`pnpm add -D ngbastion`, `yarn add -D ngbastion`).

## Dependencies of the scanned project

Installing your project's dependencies (`npm ci`) before scanning is recommended. With `node_modules` present, NgBastion identifies framework APIs through the TypeChecker. Without it, it falls back to reading import declarations and type annotations, and reports an `unresolved-imports` diagnostic so you know which mode was used.

## Run from source

To work on NgBastion itself, see [Contributing](/docs/contributing/).
