import type * as ts from 'typescript';
import { defineRule, lowerConfidence, type RuleFinding } from '@ngbastion/plugin-api';
import { flowEvidence, isGlobalCall, sinkStep, strip } from '../shared/common.js';

const ATTACKER = new Set(['url', 'message', 'window-name', 'referrer', 'user-input']);
const ESCAPE = /escape|quote|sanitiz/i;
const SERVER_FILE = /(^|[/\\])(server|main\.server|app\.config\.server)\.ts$|[/\\]server[/\\]/;

export const ngb037 = defineRule({
  meta: {
    id: 'NGB037',
    name: 'Regular expression injection',
    category: 'angular-xss',
    defaultSeverity: 'medium',
    cwe: ['CWE-1333', 'CWE-400'],
    docs: {
      description:
        "Reports regular expressions compiled from attacker-controllable text — `new RegExp(value)`, `RegExp(value)`, and `str.match(value)` / `str.search(value)` / `str.matchAll(value)` with a string argument — when the value comes from URL / route parameters, postMessage data, `window.name`, the referrer or form input and is not passed through an escaping function. Code in SSR server files is reported with high severity.",
      rationale:
        "Pattern syntax in the input changes what the expression matches (a search for `.*` matches everything, a validation regex can be bypassed) and catastrophic backtracking patterns such as `(a+)+$` freeze the tab. During server-side rendering the same code runs in Node.js, where one request with a crafted query parameter blocks the event loop for every user (ReDoS).",
      patterns: [
        '`new RegExp(v, flags)`, `RegExp(v)` (global constructor, symbol-resolved)',
        '`text.match(v)`, `text.search(v)`, `text.matchAll(v)` where `v` is a string (strings are compiled to regular expressions)',
        "Sources: ActivatedRoute / `location` values, postMessage data, `window.name`, referrer, input values and `[(ngModel)]` bindings",
        'Escaping recognized: functions whose name contains `escape`, `quote` or `sanitize` (e.g. `_.escapeRegExp`, a project `escapeRegex()`)',
        'Files named `server.ts`, `main.server.ts`, `app.config.server.ts` or under `server/` raise the severity to high',
      ],
      limitations: [
        'Whether the resulting pattern is exponential is not analyzed; any unescaped untrusted pattern is reported.',
        'Code shared between browser and SSR is reported with medium severity unless it is in a server file.',
      ],
      falsePositives: [
        'Search boxes that intentionally accept regular expressions from the user typing them only affect that user; such findings are low confidence.',
      ],
      remediation:
        "Escape user text before building a pattern (`value.replace(/[.*+?^${}()|[\\]\\\\]/g, '\\\\$&')`, lodash `escapeRegExp`), or avoid regular expressions and use `includes()` / `startsWith()` for plain-text matching. Limit input length.",
      example: {
        unsafe: `const q = this.route.snapshot.queryParamMap.get('q') ?? '';
this.results = this.items.filter((i) => new RegExp(q, 'i').test(i.name));`,
        safe: `const q = escapeRegExp(this.route.snapshot.queryParamMap.get('q') ?? '');
this.results = this.items.filter((i) => new RegExp(q, 'i').test(i.name));`,
      },
      references: [
        { title: 'OWASP — Regular expression Denial of Service (ReDoS)', url: 'https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS' },
        { title: 'MDN — Escaping regular expression input', url: 'https://developer.mozilla.org/docs/Web/JavaScript/Guide/Regular_expressions#escaping' },
      ],
    },
  },
  analyze(ctx) {
    const t = ctx.ts;
    const findings: RuleFinding[] = [];
    const check = (node: ts.Node, pattern: ts.Expression, api: string) => {
      const result = ctx.taint.trace(pattern, { context: 'generic' });
      const flow = result.flows.find((f) => ATTACKER.has(f.source.kind));
      if (!flow) return;
      if (flow.steps.some((s) => ESCAPE.test(s.description)) || result.names.some((n) => ESCAPE.test(n))) return;
      const server = SERVER_FILE.test(node.getSourceFile().fileName);
      const self = flow.source.kind === 'user-input';
      findings.push({
        node,
        message: `${api} compiles a pattern from ${flow.source.description} without escaping it; regex syntax in the value changes the match${server ? ' and can block the SSR server (ReDoS)' : ' and can freeze the page (ReDoS)'}.`,
        confidence: self ? lowerConfidence(flow.confidence) : flow.confidence,
        severity: server ? 'high' : self ? 'low' : 'medium',
        evidenceKind: 'dataflow',
        trace: [...flow.steps, sinkStep(ctx, node, api)],
        evidence: [...flowEvidence(flow), ...(server ? ['runs in an SSR server file'] : [])],
      });
    };
    for (const n of ctx.index.newExpressions) {
      const callee = strip(ctx, n.expression);
      if (t.isIdentifier(callee) && callee.text === 'RegExp' && n.arguments?.[0]) {
        const d = ctx.symbols.declarationOf(callee);
        if (!d || d.getSourceFile().isDeclarationFile) check(n, n.arguments[0], 'new RegExp()');
      }
    }
    for (const call of ctx.index.calls) {
      const info = ctx.symbols.callee(call);
      const arg = call.arguments[0];
      if (!info || !arg) continue;
      if (isGlobalCall(info, 'RegExp')) check(call, arg, 'RegExp()');
      else if (['match', 'search', 'matchAll'].includes(info.name) && !info.declaration && t.isPropertyAccessExpression(strip(ctx, call.expression))) {
        const argType = ctx.checker.getTypeAtLocation(arg);
        const recvType = ctx.checker.getTypeAtLocation((strip(ctx, call.expression) as ts.PropertyAccessExpression).expression);
        if (argType.flags & t.TypeFlags.StringLike && recvType.flags & t.TypeFlags.StringLike) check(call, arg, `String.${info.name}()`);
      }
    }
    return findings;
  },
});
