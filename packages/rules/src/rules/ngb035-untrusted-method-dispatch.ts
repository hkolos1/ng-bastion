import type * as ts from 'typescript';
import { defineRule, type AnalysisContext, type RuleFinding } from '@ngbastion/plugin-api';
import { flowEvidence, sinkStep, strip } from '../shared/common.js';
import { isGlobalObject } from './ngb028-sensitive-global-objects.js';

const ATTACKER = new Set(['url', 'message', 'window-name', 'referrer']);

/** Guard that restricts the key to own properties / an allowlist (not `in` or `typeof === 'function'`, which prototype keys pass). */
function allowlisted(ctx: AnalysisContext, node: ts.Node, keyText: string): boolean {
  return ctx.flow.guards(node).some((g) => {
    const c = g.condition.getText();
    if (!c.includes(keyText)) return false;
    return /\b(hasOwn|hasOwnProperty|includes|has|indexOf)\s*\(/.test(c) || /===\s*['"`]|['"`]\s*===/.test(c);
  });
}

export const ngb035 = defineRule({
  meta: {
    id: 'NGB035',
    name: 'Untrusted dynamic method dispatch',
    category: 'cross-window',
    defaultSeverity: 'high',
    cwe: ['CWE-470'],
    docs: {
      description:
        "Reports calls through a computed member whose name comes from an attacker-controllable source — `handlers[event.data.cmd](…)`, `this[params.get('action')]()`, `window[name](…)`, also via `.call()` / `.apply()` — without an own-property or allowlist check on the key. Sources: postMessage data, URL / route parameters, `window.name`, `document.referrer`.",
      rationale:
        "A message or link that picks the function name can call any method reachable from the object: other handlers than intended, inherited members (`constructor`, `__defineGetter__`, `toString`), and on `window` or `this` every global function or component method — including ones that navigate, post data or touch storage. `key in handlers` and `typeof handlers[key] === 'function'` do not help, because inherited members pass both.",
      patterns: [
        '`obj[key](…)`, `obj[key].call(…)`, `obj[key].apply(…)` where `key` is traced (taint engine) to `MessageEvent.data`, ActivatedRoute / `location` values, `window.name` or `document.referrer`',
        'High severity on `window` / `globalThis` / `this`; medium on handler maps',
        "Recognized allowlists guarding the call: `Object.hasOwn(map, key)`, `map.hasOwnProperty(key)`, `ALLOWED.includes(key)`, `set.has(key)`, comparisons with string literals",
      ],
      limitations: [
        'Dispatch through `Map.get(key)` is not reported (Maps have no prototype keys); only computed member calls are.',
        'Keys that pass through unmodeled libraries lose confidence or are not followed.',
      ],
      falsePositives: [
        'Handler maps created with `Object.create(null)` and frozen are safe from prototype keys but still let the sender pick any handler; the finding is still reported with medium severity.',
      ],
      remediation:
        "Dispatch with a `switch` over the expected command names, or look the handler up in a `Map` / `Object.create(null)` table after checking `Object.hasOwn(handlers, cmd)`; validate the message origin first (NGB007).",
      example: {
        unsafe: `window.addEventListener('message', (e) => this[e.data.method](...e.data.args));`,
        safe: `const HANDLERS = new Map([['resize', (a) => this.resize(a)], ['close', () => this.close()]]);
window.addEventListener('message', (e) => {
  if (e.origin !== PARENT_ORIGIN) return;
  HANDLERS.get(e.data.method)?.(e.data.args);
});`,
      },
      references: [
        { title: 'CWE-470 — Use of Externally-Controlled Input to Select Classes or Code', url: 'https://cwe.mitre.org/data/definitions/470.html' },
      ],
    },
  },
  analyze(ctx) {
    const t = ctx.ts;
    const findings: RuleFinding[] = [];
    for (const call of ctx.index.calls) {
      let target = strip(ctx, call.expression);
      // obj[key].call(...) / .apply(...)
      if (t.isPropertyAccessExpression(target) && ['call', 'apply', 'bind'].includes(target.name.text)) target = strip(ctx, target.expression);
      if (!t.isElementAccessExpression(target)) continue;
      const key = target.argumentExpression;
      if (ctx.symbols.constantString(key) !== undefined || t.isNumericLiteral(key)) continue;
      const result = ctx.taint.trace(key, { context: 'generic' });
      const flow = result.flows.find((f) => ATTACKER.has(f.source.kind));
      if (!flow || allowlisted(ctx, call, strip(ctx, key).getText())) continue;
      const recv = strip(ctx, target.expression);
      const broad = recv.kind === t.SyntaxKind.ThisKeyword || isGlobalObject(ctx, recv);
      findings.push({
        node: call,
        message: `Method name comes from ${flow.source.description}; the sender can invoke any ${broad ? (recv.kind === t.SyntaxKind.ThisKeyword ? 'method of this class' : 'global function') : `property of '${recv.getText().slice(0, 40)}'`}, including inherited members.`,
        confidence: flow.confidence,
        severity: broad ? 'high' : 'medium',
        evidenceKind: 'dataflow',
        trace: [...flow.steps, sinkStep(ctx, call, 'computed method call')],
        evidence: [...flowEvidence(flow), 'no own-property / allowlist check on the key'],
      });
    }
    return findings;
  },
});
