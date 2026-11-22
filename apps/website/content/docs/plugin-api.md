---
title: Plugin API
description: Write and load trusted custom NgBastion rules with the versioned plugin API.
---

Custom rules implement the same contract as built-in rules (`@ngbastion/plugin-api`, `PLUGIN_API_VERSION = 1`).

:::danger[Plugins are trusted code]
A plugin is an ordinary JavaScript module running inside the scanner's Node.js process. The API contract is **not a sandbox**: a plugin can read files, use the network and do anything the user running the scan can do. Only configure plugins you trust and review.
:::

## A rule

```js
// acme-rules.mjs
export default {
  apiVersion: 1,
  name: 'acme-rules',
  rules: [
    {
      meta: {
        id: 'ACME001',
        name: 'No document.domain writes',
        category: 'custom',
        defaultSeverity: 'medium',
        docs: {
          description: 'Flags assignments to document.domain.',
          rationale: 'Relaxing document.domain weakens the same-origin policy.',
          patterns: ['document.domain = …'],
          limitations: [],
          falsePositives: [],
          remediation: 'Use postMessage with an explicit origin instead.',
          example: { unsafe: "document.domain = 'example.com';", safe: '' },
        },
      },
      analyze(ctx) {
        return ctx.index.assignments
          .filter((a) => a.left.getText() === 'document.domain')
          .map((a) => ({ node: a, message: 'document.domain is assigned', confidence: 'high', evidenceKind: 'pattern' }));
      },
    },
  ],
};
```

In TypeScript, `definePlugin()` and `defineRule()` from `@ngbastion/plugin-api` add type checking.

## Loading

```json
{ "plugins": ["./acme-rules.mjs", "@acme/ngbastion-rules"] }
```

Relative paths resolve from the declaring config file; package names resolve from local `node_modules`. Remote URLs are rejected. A plugin's rules are enabled as `error` unless configured otherwise.

Validation at load time (exit code `2` on failure):

- `apiVersion` must equal the scanner's plugin API version;
- `name` and at least one rule are required;
- rule IDs must look like `ACME001`, must be unique, and the `NGB` prefix is reserved;
- each rule needs `analyze`, a name, a valid default severity, and `docs.description` / `docs.remediation`.

## The analysis context

`analyze(ctx)` receives a read-only context:

| Member | Use |
|---|---|
| `ts`, `program`, `checker` | TypeScript Compiler API objects |
| `project` | Name, roots, Angular version, `index.html`, `angular.json` entry |
| `sourceFiles` | In-scope files (exclusions applied) |
| `templates` | Parsed component templates: elements, attributes, bindings |
| `index` | `calls`, `newExpressions`, `assignments`, `classes`, `stringLiterals`, `callsTo()` |
| `taint.trace(expr, { context })` | Source-to-sink flows, unresolved origins, sanitizers, constants |
| `symbols` | `typeOrigin()`, `callee()`, `constantString()`, `declarationOf()`, `propertyNames()` |
| `flow` | `guards()`, `enclosingFunction()`, `resolveFunction()` |
| `options` | Rule options from configuration |
| `readFile()`, `findFiles()` | Read-only access to non-TypeScript files inside the workspace |
| `diagnostic()` | Report a limitation or unsupported construct |

A finding needs a `node` or `location`, a `message`, a `confidence` and an `evidenceKind`. Include a `trace` only with steps that were actually observed.
