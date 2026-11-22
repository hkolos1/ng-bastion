import type * as ts from 'typescript';
import { defineRule, type RuleFinding } from '@ngbastion/plugin-api';
import { is, isGlobalCall, memberName, receiverOf, reportSink, strip } from '../shared/common.js';

export const ngb004 = defineRule({
  meta: {
    id: 'NGB004',
    name: 'Dynamic code execution',
    category: 'angular-xss',
    defaultSeverity: 'critical',
    cwe: ['CWE-95'],
    docs: {
      description:
        'Reports untrusted data reaching string-based JavaScript execution: `eval()`, `Function()` / `new Function()`, and `setTimeout()` / `setInterval()` with a string argument. Constant code strings are not reported; dynamic code of unknown origin is reported with low confidence.',
      rationale:
        'These APIs compile strings into code that runs with the full privileges of your application. Attacker-controlled input reaching them is direct script injection, regardless of Angular sanitization. They also require `unsafe-eval` in a Content Security Policy.',
      patterns: [
        '`eval(code)`, `window.eval(code)`, `globalThis.eval(code)` resolved to the global `eval`',
        '`new Function(...args)` and `Function(...args)` (every argument is traced)',
        '`setTimeout(code, …)` / `setInterval(code, …)` when `code` is not a function',
        'A local function that shadows `eval` is not reported (symbols are resolved, not matched by name)',
      ],
      limitations: [
        'Indirect references (`const e = eval; e(x)`) are not followed.',
        'Execution through third-party template engines or `vm`-like libraries is not modeled.',
      ],
      falsePositives: ['Expressions built only from developer-controlled configuration can still be reported when that configuration is loaded at runtime (HTTP / storage).'],
      remediation:
        'Remove string-based code execution. Use a lookup table of functions, `JSON.parse()` for data, or a purpose-built expression parser that does not execute JavaScript.',
      example: {
        unsafe: `const formula = this.route.snapshot.queryParams['f'];
const result = eval(formula);`,
        safe: `const OPS = { sum: (a: number, b: number) => a + b } as const;
const op = OPS[this.route.snapshot.queryParams['op'] as keyof typeof OPS];
const result = op ? op(1, 2) : undefined;`,
      },
      references: [{ title: 'MDN — Never use eval()', url: 'https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/eval#never_use_direct_eval!' }],
    },
  },
  analyze(ctx) {
    const t = ctx.ts;
    const findings: RuleFinding[] = [];
    const report = (sink: ts.Node, value: ts.Expression, api: string) => findings.push(...reportSink({
      ctx,
      sink,
      value,
      context: 'code',
      sinkDescription: `${api} executes the string as JavaScript`,
      message: (f) => `Untrusted data (${f.source.description}) is executed as code by ${api}.`,
      unresolvedMessage: `${api} executes a dynamic string whose origin could not be determined.`,
    }));
    const isFunctionValue = (e: ts.Expression) => {
      const x = strip(ctx, e);
      if (t.isArrowFunction(x) || t.isFunctionExpression(x)) return true;
      const type = ctx.checker.getTypeAtLocation(x);
      return type.getCallSignatures().length > 0;
    };

    for (const call of ctx.index.calls) {
      const info = ctx.symbols.callee(call);
      if (!info) continue;
      const callee = strip(ctx, call.expression);
      const recv = receiverOf(ctx, callee);
      const globalRecv = recv && is(ctx.symbols.typeOrigin(recv), 'dom', 'Window');
      const globalish = (!recv && isGlobalCall(info, info.name)) || (globalRecv && !info.declaration) || (recv && t.isIdentifier(strip(ctx, recv)) && (strip(ctx, recv) as ts.Identifier).text === 'globalThis');
      if (!globalish) continue;
      if (info.name === 'eval' && call.arguments[0]) report(call, call.arguments[0], 'eval()');
      else if (info.name === 'Function' && !recv) for (const a of call.arguments) report(call, a, 'Function()');
      else if ((info.name === 'setTimeout' || info.name === 'setInterval') && call.arguments[0] && !isFunctionValue(call.arguments[0])) {
        report(call, call.arguments[0], `${info.name}() with a string`);
      }
    }
    for (const n of ctx.index.newExpressions) {
      const callee = strip(ctx, n.expression);
      if (t.isIdentifier(callee) && callee.text === 'Function' && memberName(ctx, callee) === undefined) {
        const info = ctx.symbols.callee(n);
        if (info?.declaration) continue;
        for (const a of n.arguments ?? []) report(n, a, 'new Function()');
      }
    }
    // De-duplicate: one finding per call (Function() reports per argument).
    const seen = new Set<ts.Node>();
    return findings.filter((f) => (seen.has(f.node!) ? false : (seen.add(f.node!), true)));
  },
});
