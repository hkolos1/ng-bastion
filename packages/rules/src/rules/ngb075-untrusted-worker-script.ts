import type * as ts from 'typescript';
import { defineRule, type AnalysisContext, type RuleFinding } from '@ngbastion/plugin-api';
import { is, memberName, receiverOf, strip } from '../shared/common.js';
import { flowFinding, taintedFlow } from '../shared/server-flow.js';

/** Sources an attacker controls for another user's browser (as NGB005 / NGB026). */
const ATTACKER = ['url', 'message', 'window-name', 'referrer', 'http-response', 'storage'] as const;

/** `new Worker(...)` / `new SharedWorker(...)` with the DOM constructor (not a project class of that name). */
function workerCtor(ctx: AnalysisContext, n: ts.NewExpression): string | undefined {
  const t = ctx.ts;
  const callee = strip(ctx, n.expression);
  const name = t.isIdentifier(callee) ? callee.text : memberName(ctx, callee);
  if (name !== 'Worker' && name !== 'SharedWorker') return undefined;
  const decl = ctx.symbols.declarationOf(callee);
  if (decl && !decl.getSourceFile().isDeclarationFile) return undefined;
  return name;
}

/** `URL.createObjectURL(new Blob([...parts]))` → the Blob parts (worker code). */
function blobParts(ctx: AnalysisContext, e: ts.Expression): ts.Expression[] | undefined {
  const t = ctx.ts;
  let x = strip(ctx, e);
  if (t.isIdentifier(x)) {
    const d = ctx.symbols.declarationOf(x);
    if (d && t.isVariableDeclaration(d) && d.initializer) x = strip(ctx, d.initializer);
  }
  if (!t.isCallExpression(x) || memberName(ctx, x.expression) !== 'createObjectURL' || !x.arguments[0]) return undefined;
  let blob = strip(ctx, x.arguments[0]);
  if (t.isIdentifier(blob)) {
    const d = ctx.symbols.declarationOf(blob);
    if (d && t.isVariableDeclaration(d) && d.initializer) blob = strip(ctx, d.initializer);
  }
  if (!t.isNewExpression(blob) || strip(ctx, blob.expression).getText() !== 'Blob' || !blob.arguments?.[0]) return undefined;
  const arr = strip(ctx, blob.arguments[0]);
  return t.isArrayLiteralExpression(arr) ? [...arr.elements] : [arr];
}

export const ngb075 = defineRule({
  meta: {
    id: 'NGB075',
    name: 'Untrusted worker script',
    category: 'angular-xss',
    defaultSeverity: 'high',
    cwe: ['CWE-829', 'CWE-94'],
    docs: {
      description:
        "Traces untrusted data (URL, postMessage data, `window.name`, referrer, HTTP responses, storage) into the script that a Web Worker, Shared Worker or service worker runs: the URL of `new Worker(url)`, `new SharedWorker(url)` and `navigator.serviceWorker.register(url)`, and the code of Blob workers (`new Worker(URL.createObjectURL(new Blob([code])))`). `importScripts()` inside workers is NGB005.",
      rationale:
        "A worker runs with the page's origin: it can call your APIs with the user's cookies, read IndexedDB and CacheStorage, and post forged messages to the page. A service worker is worse — once registered it intercepts every request of its scope and survives reloads. Letting the URL or the code come from a query parameter or a message is script injection.",
      patterns: [
        "`new Worker(url)`, `new SharedWorker(url)` (DOM constructors), `navigator.serviceWorker.register(url)` / `ServiceWorkerContainer.register(url)` with a traced untrusted URL (`data:` and `blob:` URLs built from untrusted text included)",
        '`new Worker(URL.createObjectURL(new Blob([code])))` with untrusted `code`',
        "Not reported: `new Worker(new URL('./app.worker', import.meta.url))` (Angular CLI worker bundles), constant URLs",
      ],
      limitations: [
        'Blob workers are followed when the Blob and object URL are created inline or in a local `const`.',
        'Worker URLs validated by an allowlist are still reported (the check is not recognized).',
      ],
      falsePositives: [
        'A worker URL chosen from a server response you fully control (configuration API) is reported with medium confidence; pin it to a constant or document an exception.',
      ],
      remediation:
        "Load workers only from constant, same-origin URLs (`new Worker(new URL('./x.worker', import.meta.url))`) and register service workers from a fixed path. Pass untrusted data to the worker as messages, never as its URL or code.",
      example: {
        unsafe: "const worker = new Worker(this.route.snapshot.queryParams['engine']);",
        safe: "const worker = new Worker(new URL('./engine.worker', import.meta.url), { type: 'module' });",
      },
      references: [
        { title: 'MDN — Worker() constructor', url: 'https://developer.mozilla.org/docs/Web/API/Worker/Worker' },
        { title: 'Angular — Background processing using web workers', url: 'https://angular.dev/ecosystem/web-workers' },
      ],
    },
  },
  analyze(ctx) {
    const findings: RuleFinding[] = [];
    const report = (node: ts.Node, value: ts.Expression, what: string, context: 'resource-url' | 'code') => {
      const tv = taintedFlow(ctx, value, { context, kinds: [...ATTACKER] });
      if (!tv) return false;
      findings.push(flowFinding(ctx, node, tv, what, `Untrusted data (${tv.flow.source.description}) ${context === 'code' ? 'becomes the code' : 'chooses the script URL'} of ${what}; the script runs with this origin's privileges.`, tv.flow.source.kind === 'http-response' || tv.flow.source.kind === 'storage' ? { severity: 'medium' } : {}));
      return true;
    };
    for (const n of ctx.index.newExpressions) {
      const ctor = workerCtor(ctx, n);
      const arg = n.arguments?.[0];
      if (!ctor || !arg) continue;
      const parts = blobParts(ctx, arg);
      if (parts) {
        for (const p of parts) if (report(n, p, `a Blob ${ctor}`, 'code')) break;
      } else report(n, arg, `new ${ctor}()`, 'resource-url');
    }
    for (const call of ctx.index.calls) {
      const callee = strip(ctx, call.expression);
      if (memberName(ctx, callee) !== 'register' || !call.arguments[0]) continue;
      const recv = receiverOf(ctx, callee)!;
      const typed = is(ctx.symbols.typeOrigin(recv), 'dom', 'ServiceWorkerContainer');
      if (!typed && memberName(ctx, recv) !== 'serviceWorker') continue;
      report(call, call.arguments[0], 'navigator.serviceWorker.register()', 'resource-url');
    }
    return findings;
  },
});
