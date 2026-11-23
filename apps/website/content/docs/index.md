---
title: What is NgBastion?
description: NgBastion is an Angular-aware, local-first security scanner that traces untrusted data from sources to dangerous sinks in Angular applications.
---

NgBastion is an open-source static security analyzer for Angular applications. It reads your TypeScript and Angular templates with the TypeScript Compiler API and the Angular template parser, follows untrusted values through your code, and reports where they reach security-sensitive operations — with the evidence it used.

It runs entirely on your machine. Source code is never uploaded, and there is no telemetry.

## What it does

- **Understands Angular.** It knows that `[innerHTML]` template bindings are sanitized by Angular and does not report them. It recognizes `DomSanitizer`, `ElementRef`, `Renderer2`, `ActivatedRoute`, `HttpClient`, HTTP interceptors, `TransferState`, signals, `inject()` and template two-way bindings.
- **Traces data flow.** A finding such as "query parameter reaches `bypassSecurityTrustHtml()`" comes with the path it followed — across services, files, RxJS operators and signals — so you can verify it yourself.
- **Separates severity from confidence.** A critical sink reached through a heuristic match is reported as critical with *low* confidence, not as a certainty.
- **Says what it could not see.** Unsupported constructs, unresolved imports and analysis limits are reported as diagnostics instead of being silently ignored.
- **Fits CI.** Terminal, JSON and SARIF 2.1.0 output, configurable gates and predictable exit codes.

## What it is not

NgBastion is not a penetration test, a server-side authorization review or a replacement for browser security controls such as Content Security Policy. It reports the patterns and data flows it models — [20 rules](/rules/) in version 0.1 — and nothing else. **No findings does not mean an application is secure.**

## Next steps

- [Install and run it](/docs/getting-started/installation/)
- [Run a first scan](/docs/getting-started/first-scan/)
- [Learn to read findings](/docs/getting-started/reading-findings/)
