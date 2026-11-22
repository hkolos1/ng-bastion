# Third-party notices

NgBastion's published packages depend at runtime on:

| Package | License | Used for |
|---|---|---|
| [typescript](https://github.com/microsoft/TypeScript) | Apache-2.0 | Compiler API, TypeChecker, bundled `lib.*.d.ts` |
| [@angular/compiler](https://github.com/angular/angular) | MIT | Angular template parsing |
| [picomatch](https://github.com/micromatch/picomatch) | MIT | File glob matching |

Development and test tooling (pnpm, Turborepo, tsup, Vitest, ESLint, Ajv, Astro, Starlight) is not
distributed with the scanner.

`tests/fixtures/schemas/sarif-2.1.0.json` is the SARIF 2.1.0 JSON schema published by the OASIS
Static Analysis Results Interchange Format (SARIF) TC (via schemastore.org), used only to validate
generated reports in tests.

NgBastion is an independent project and is not affiliated with or endorsed by Google or the Angular
team. "Angular" is a trademark of Google LLC.
