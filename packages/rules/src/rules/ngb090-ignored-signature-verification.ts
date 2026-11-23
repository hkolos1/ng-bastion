import type * as ts from 'typescript';
import { defineRule, type AnalysisContext, type RuleFinding } from '@ngbastion/plugin-api';
import { is, memberName, receiverOf, strip } from '../shared/common.js';
import { NODE_CRYPTO, nodeCryptoCall, subtleCall } from '../shared/crypto.js';

/** `x.verify(…)` where `x` is a Node `crypto.Verify` (typed, `createVerify()` binding or chain). */
function isNodeVerifier(ctx: AnalysisContext, call: ts.CallExpression): boolean {
  const t = ctx.ts;
  if (memberName(ctx, call.expression) !== 'verify') return false;
  const info = ctx.symbols.callee(call);
  if (info?.declaration) return false;
  if (is(info?.receiver, NODE_CRYPTO, 'Verify')) return true;
  let recv = receiverOf(ctx, strip(ctx, call.expression));
  // createVerify('sha256').update(data).verify(key, sig)
  for (let i = 0; recv && i < 4; i++) {
    const r: ts.Expression = strip(ctx, recv);
    if (t.isCallExpression(r)) {
      if (nodeCryptoCall(ctx, r, ['createVerify'])) return true;
      if (['update', 'end', 'write'].includes(memberName(ctx, r.expression) ?? '')) { recv = receiverOf(ctx, strip(ctx, r.expression)); continue; }
      return false;
    }
    if (t.isIdentifier(r)) {
      const d = ctx.symbols.declarationOf(r);
      if (d && t.isVariableDeclaration(d) && d.initializer) { recv = d.initializer; continue; }
    }
    return false;
  }
  return false;
}

/** Outermost expression that carries the call's value (`await`, parentheses, casts, `.then()` receiver excluded). */
function valueNode(ctx: AnalysisContext, call: ts.Node): ts.Node {
  const t = ctx.ts;
  let n = call;
  while (n.parent && (t.isAwaitExpression(n.parent) || t.isParenthesizedExpression(n.parent) || t.isAsExpression(n.parent) || t.isNonNullExpression(n.parent))) n = n.parent;
  return n;
}

/** Why the verification result is discarded, or undefined when it is used. */
function discarded(ctx: AnalysisContext, call: ts.CallExpression): string | undefined {
  const t = ctx.ts;
  const v = valueNode(ctx, call);
  const p = v.parent;
  if (!p) return undefined;
  if (t.isExpressionStatement(p)) return 'the call is a statement; its result is never read';
  if (t.isVoidExpression(p)) return 'the result is discarded with void';
  if (t.isVariableDeclaration(p) && p.initializer === v && t.isIdentifier(p.name)) {
    const name = p.name.text;
    const scope = ctx.flow.enclosingFunction(p) ?? p.getSourceFile();
    let used = false;
    const visit = (n: ts.Node): void => {
      if (used) return;
      if (t.isIdentifier(n) && n.text === name && n !== p.name && ctx.symbols.declarationOf(n) === p) used = true;
      t.forEachChild(n, visit);
    };
    visit(scope);
    return used ? undefined : `the result is stored in '${name}' but never read`;
  }
  // `.then(() => …)` that ignores its argument
  if (t.isPropertyAccessExpression(p) && p.name.text === 'then' && t.isCallExpression(p.parent) && p.parent.expression === p) {
    const cb = p.parent.arguments[0];
    if (cb && (t.isArrowFunction(cb) || t.isFunctionExpression(cb)) && cb.parameters.length === 0) return 'the then() callback ignores the verification result';
  }
  return undefined;
}

export const ngb090 = defineRule({
  meta: {
    id: 'NGB090',
    name: 'Signature verification result ignored',
    category: 'cryptography',
    defaultSeverity: 'high',
    cwe: ['CWE-347', 'CWE-252'],
    docs: {
      description:
        'Reports signature / MAC verification calls whose boolean result is never used: `crypto.subtle.verify()` (awaited or not), Node `crypto.verify()` and `crypto.Verify#verify()` (from `createVerify()`), when the call is an expression statement, discarded with `void`, stored in a variable that is never read, or followed by a `.then()` callback that ignores its argument.',
      rationale:
        'Unlike libraries that throw on a bad signature, these APIs only return `false`. Calling them without checking the result looks like verification in code review but accepts every forged message, token, license or webhook — the same as not verifying at all.',
      patterns: [
        '`await crypto.subtle.verify(alg, key, sig, data);` as a statement (also without `await`, or with `void`)',
        '`const ok = await crypto.subtle.verify(…)` where `ok` is never read',
        "`crypto.verify('sha256', data, key, sig);` (sync form) and `createVerify('sha256').update(data).verify(key, sig);` / `verifier.verify(key, sig);` as statements",
        '`crypto.subtle.verify(…).then(() => …)` with a callback that takes no parameter',
      ],
      limitations: [
        'A result that is read but compared incorrectly (`if (ok !== undefined)`) is not detected.',
        "`crypto.verify()` with a callback reports its result through the callback, which is not analyzed.",
        'JWT / JOSE libraries (which throw on failure) are not in scope.',
      ],
      falsePositives: [
        'Verification run only for timing or side effects (benchmarks) is reported; such code should not live in production paths.',
      ],
      remediation:
        'Branch on the result and reject the input when it is `false`: `if (!(await crypto.subtle.verify(alg, key, sig, data))) throw new Error("invalid signature");`.',
      example: {
        unsafe: "await crypto.subtle.verify('HMAC', key, signature, payload);\nreturn JSON.parse(text);",
        safe: "if (!(await crypto.subtle.verify('HMAC', key, signature, payload))) throw new Error('invalid signature');\nreturn JSON.parse(text);",
      },
      references: [
        { title: 'MDN — SubtleCrypto.verify() return value', url: 'https://developer.mozilla.org/docs/Web/API/SubtleCrypto/verify' },
        { title: 'Node.js — crypto.verify()', url: 'https://nodejs.org/api/crypto.html#cryptoverifyalgorithm-data-key-signature-callback' },
      ],
    },
  },
  analyze(ctx) {
    const findings: RuleFinding[] = [];
    for (const call of ctx.index.calls) {
      let api: string | undefined;
      if (subtleCall(ctx, call, ['verify'])) api = 'crypto.subtle.verify()';
      else if (nodeCryptoCall(ctx, call, ['verify']) && call.arguments.length < 5) api = 'crypto.verify()';
      else if (isNodeVerifier(ctx, call)) api = 'Verify#verify()';
      if (!api) continue;
      const why = discarded(ctx, call);
      if (!why) continue;
      findings.push({
        node: call,
        message: `${api} returns false for an invalid signature instead of throwing, but ${why}: forged data is accepted.`,
        confidence: 'high',
        evidenceKind: 'pattern',
        evidence: [why],
      });
    }
    return findings;
  },
});
