import type * as ts from 'typescript';
import { defineRule, type AnalysisContext, type RuleFinding, type TaintFlow } from '@ngbastion/plugin-api';
import { flowEvidence, is, sinkStep, strip } from '../shared/common.js';

const ATTACKER = new Set(['url', 'message', 'window-name', 'referrer']);
const LODASH = ['lodash', 'lodash-es', 'lodash/merge', 'lodash/mergeWith', 'lodash/defaultsDeep', 'lodash/set', 'lodash/setWith', 'lodash/zipObjectDeep', 'lodash.merge', 'lodash.set', 'lodash.defaultsdeep', 'lodash.mergewith'];
/** Deep-merge style functions: argument indexes that are merged / used as a path. */
const MERGERS: Record<string, { args: number[]; what: 'source' | 'path' }> = {
  merge: { args: [1, 2, 3], what: 'source' },
  mergeWith: { args: [1, 2], what: 'source' },
  defaultsDeep: { args: [1, 2, 3], what: 'source' },
  set: { args: [1], what: 'path' },
  setWith: { args: [1], what: 'path' },
  zipObjectDeep: { args: [0], what: 'path' },
};
const KEY_GUARD = /__proto__|constructor|prototype|hasOwn|hasOwnProperty|Object\.create\(null\)|includes\(|\.has\(/;

function attackerFlow(ctx: AnalysisContext, e: ts.Expression): TaintFlow | undefined {
  return ctx.taint.trace(e, { context: 'generic' }).flows.find((f) => ATTACKER.has(f.source.kind));
}

function guarded(ctx: AnalysisContext, node: ts.Node): boolean {
  return ctx.flow.guards(node).some((g) => KEY_GUARD.test(g.condition.getText()));
}

export const ngb036 = defineRule({
  meta: {
    id: 'NGB036',
    name: 'Prototype pollution',
    category: 'angular-xss',
    defaultSeverity: 'high',
    cwe: ['CWE-1321'],
    docs: {
      description:
        "Reports attacker-controllable objects or property paths flowing into operations that can write to `Object.prototype`: deep merges (`_.merge`, `mergeWith`, `defaultsDeep`, jQuery `$.extend(true, …)`, `deepmerge`), path setters (`_.set(obj, path, v)`, `setWith`, `zipObjectDeep`) and nested computed assignments `obj[a][b] = v` where both keys come from postMessage data, URL parameters, `window.name` or the referrer.",
      rationale:
        "`JSON.parse` turns `{\"__proto__\": {\"isAdmin\": true}}` into an object with an own `__proto__` key; a deep merge then copies it onto `Object.prototype`, and every object in the page suddenly has `isAdmin === true`. In browsers this commonly becomes XSS through script gadgets (`innerHTML` options, sanitizer configs, template settings read from plain objects) or bypasses client-side checks.",
      patterns: [
        "lodash / lodash-es / per-method packages: `merge`, `mergeWith`, `defaultsDeep` (source arguments), `set`, `setWith` (path argument), `zipObjectDeep` (paths)",
        "`$.extend(true, target, source)` / `jQuery.extend(true, …)`, `deepmerge(a, b)` / `deepmerge.all([...])`",
        '`obj[k1][k2] = value` with `k1` traced to an attacker source and `k2` (or the value) also attacker-controlled',
        "Guards that check `__proto__` / `constructor` / `prototype`, `hasOwnProperty`, `Object.hasOwn` or an allowlist suppress the computed-assignment finding",
      ],
      limitations: [
        'Hand-written recursive merge functions are only covered when the nested assignment pattern is visible; recursion depth is not modeled.',
        'Library versions are not checked: patched lodash versions still pollute through `merge` with `constructor.prototype` paths in some configurations, so all calls are reported.',
        'HTTP responses and Web Storage are not treated as attacker-controlled here.',
      ],
      falsePositives: [
        'Merging a message payload that was already validated by a schema in another function is reported; schema validation is only recognized by NGB009.',
      ],
      remediation:
        "Never deep-merge untrusted objects. Validate messages and URL-derived data against a schema and copy known fields explicitly; when dynamic keys are needed, use `Map` or `Object.create(null)` and reject `__proto__`, `constructor` and `prototype`. Freezing `Object.prototype` at startup (`Object.freeze(Object.prototype)`) blocks the class entirely if your dependencies allow it.",
      example: {
        unsafe: `window.addEventListener('message', (e) => _.merge(this.settings, JSON.parse(e.data)));`,
        safe: `window.addEventListener('message', (e) => {
  if (e.origin !== EDITOR_ORIGIN) return;
  const { theme, fontSize } = SettingsSchema.parse(JSON.parse(e.data));
  this.settings = { ...this.settings, theme, fontSize };
});`,
      },
      references: [
        { title: 'OWASP — Prototype Pollution Prevention', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Prototype_Pollution_Prevention_Cheat_Sheet.html' },
        { title: 'PortSwigger — Client-side prototype pollution', url: 'https://portswigger.net/web-security/prototype-pollution/client-side' },
      ],
    },
  },
  analyze(ctx) {
    const t = ctx.ts;
    const findings: RuleFinding[] = [];
    const push = (node: ts.Node, flow: TaintFlow, api: string, what: string) => findings.push({
      node,
      message: `${api} receives ${what} from ${flow.source.description}; keys such as __proto__ can modify Object.prototype for the whole page.`,
      confidence: flow.confidence,
      evidenceKind: 'dataflow',
      trace: [...flow.steps, sinkStep(ctx, node, api)],
      evidence: flowEvidence(flow),
    });
    for (const call of ctx.index.calls) {
      const info = ctx.symbols.callee(call);
      if (!info || info.declaration) continue;
      const fromLodash = is(info.origin, LODASH) || is(info.receiver, LODASH) || (info.origin?.module.startsWith('lodash') ?? false);
      const fromModule = info.origin && /^lodash[./]/.test(info.origin.module) ? info.origin.module.split(/[./]/).pop()!.replace('defaultsdeep', 'defaultsDeep').replace('mergewith', 'mergeWith') : undefined;
      const key = Object.hasOwn(MERGERS, info.name) ? info.name : fromModule && Object.hasOwn(MERGERS, fromModule) ? fromModule : undefined;
      const spec = key ? MERGERS[key] : undefined;
      if (fromLodash && spec) {
        for (const i of spec.args) {
          const a = call.arguments[i];
          const flow = a && attackerFlow(ctx, a);
          if (flow) {
            push(call, flow, `${info.name}() (lodash)`, spec.what === 'path' ? 'a property path' : 'an object');
            break;
          }
        }
        continue;
      }
      // $.extend(true, target, ...sources)
      if (info.name === 'extend' && call.arguments[0]?.kind === t.SyntaxKind.TrueKeyword && /^(\$|jQuery)$/.test(strip(ctx, (call.expression as ts.PropertyAccessExpression).expression ?? call.expression).getText())) {
        const flow = call.arguments.slice(2).map((a) => attackerFlow(ctx, a)).find(Boolean);
        if (flow) push(call, flow, '$.extend(true, …)', 'an object');
        continue;
      }
      if ((info.name === 'deepmerge' || info.name === 'default' || info.name === 'all') && (is(info.origin, 'deepmerge') || is(info.receiver, 'deepmerge'))) {
        const flow = call.arguments.map((a) => attackerFlow(ctx, a)).find(Boolean);
        if (flow) push(call, flow, 'deepmerge()', 'an object');
      }
    }
    // obj[a][b] = v
    for (const a of ctx.index.assignments) {
      if (a.operatorToken.kind !== t.SyntaxKind.EqualsToken) continue;
      const left = strip(ctx, a.left);
      if (!t.isElementAccessExpression(left)) continue;
      const inner = strip(ctx, left.expression);
      if (!t.isElementAccessExpression(inner)) continue;
      const outerKey = attackerFlow(ctx, inner.argumentExpression);
      if (!outerKey) continue;
      const second = attackerFlow(ctx, left.argumentExpression) ?? attackerFlow(ctx, a.right);
      if (!second || guarded(ctx, a)) continue;
      push(a, outerKey, 'Nested computed assignment obj[key][key2] = value', 'both property names');
    }
    return findings;
  },
});
