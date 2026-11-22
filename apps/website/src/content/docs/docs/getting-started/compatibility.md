---
title: Project compatibility
description: Angular, TypeScript and Node.js versions supported by NgBastion 0.1.
---

| | Supported |
|---|---|
| Angular | 20, 21 and 22 — verified by compatibility fixtures in `examples/angular-20`, `examples/angular-21` and `examples/angular-22` |
| Templates | Inline and external templates, control flow (`@if`, `@for`, `@switch`, `@defer`, `@let`), parsed with the Angular 22 template parser |
| Scanner runtime | Node.js 22.22.3+ (22.x) or 24.15.0+ (24.x) |
| Bundled TypeScript | 6.0 (used to parse your sources; your project's TypeScript version does not need to match) |

The scanned application is never built, served or executed, and NgBastion adds no runtime dependency to it.

Other Angular versions are analyzed, but NgBastion reports an `angular-version-unsupported` warning because they are not covered by tests. The Angular version is read from the installed `@angular/core`, or from `package.json` when dependencies are not installed.

The compatibility suite runs the same code against each Angular version, asserts the exact expected findings, checks that framework types resolve through the TypeChecker, and checks that all three versions produce identical results.
