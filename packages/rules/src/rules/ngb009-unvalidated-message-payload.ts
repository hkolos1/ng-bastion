import type * as ts from 'typescript';
import { defineRule, minConfidence, type Confidence, type RuleFinding, type TaintFlow } from '@ngbastion/plugin-api';
import { flowEvidence, is, memberName, receiverOf, sinkStep, strip } from '../shared/common.js';
import { findMessageHandlers, handlerScopes, readCheck, type MessageHandler } from '../shared/messages.js';

const HTML_PROPS = new Set(['innerHTML', 'outerHTML', 'srcdoc', 'href', 'src', 'cookie']);
const HTTP = new Set(['get', 'post', 'put', 'patch', 'delete', 'request']);

type Validation = 'full' | 'predicate' | 'discriminant' | undefined;
const rank = (v: Validation) => ({ full: 3, predicate: 2, discriminant: 1 } as Record<string, number>)[v ?? ''] ?? 0;
const best = (a: Validation, b: Validation): Validation => (rank(a) >= rank(b) ? a : b);

/** Sensitive operations: [operation label, value expressions]. */
function sensitiveOperations(ctx: Parameters<typeof findMessageHandlers>[0]): { node: ts.Node; label: string; values: ts.Expression[] }[] {
  const t = ctx.ts;
  const out: { node: ts.Node; label: string; values: ts.Expression[] }[] = [];
  for (const a of ctx.index.assignments) {
    const prop = memberName(ctx, a.left);
    if (prop && HTML_PROPS.has(prop)) out.push({ node: a, label: `${prop} assignment`, values: [a.right] });
    else if (t.isIdentifier(strip(ctx, a.left)) && (strip(ctx, a.left) as ts.Identifier).text === 'location') out.push({ node: a, label: 'location assignment', values: [a.right] });
  }
  for (const call of ctx.index.calls) {
    const info = ctx.symbols.callee(call);
    if (!info || info.declaration) continue;
    const recv = receiverOf(ctx, strip(ctx, call.expression));
    const n = info.name;
    const args = [...call.arguments];
    if (n === 'eval' || n === 'Function' || n === 'insertAdjacentHTML' || n === 'write' || n === 'writeln' || n.startsWith('bypassSecurityTrust')) out.push({ node: call, label: `${n}()`, values: args });
    else if (n === 'setItem' && is(info.receiver, 'dom', 'Storage')) out.push({ node: call, label: 'Web Storage setItem()', values: args });
    else if ((n === 'navigate' || n === 'navigateByUrl') && (!info.receiver || is(info.receiver, '@angular/router', 'Router'))) out.push({ node: call, label: `Router.${n}()`, values: args });
    else if (HTTP.has(n) && is(info.receiver, '@angular/common/http', 'HttpClient')) out.push({ node: call, label: `HttpClient.${n}()`, values: args });
    else if (n === 'fetch' && !recv) out.push({ node: call, label: 'fetch()', values: args });
    else if ((n === 'assign' || n === 'replace') && is(info.receiver, 'dom', 'Location')) out.push({ node: call, label: `location.${n}()`, values: args });
    else if (n === 'open' && is(info.receiver, 'dom', 'Window')) out.push({ node: call, label: 'window.open()', values: args.slice(0, 1) });
    else if ((n === 'setProperty' || n === 'setAttribute') && is(info.receiver, '@angular/core', 'Renderer2')) out.push({ node: call, label: `Renderer2.${n}()`, values: args.slice(2) });
  }
  return out;
}

/** How strongly a guard condition validates the payload's runtime shape. */
function classifyValidation(ctx: Parameters<typeof findMessageHandlers>[0], cond: ts.Expression): Validation {
  const t = ctx.ts;
  let result: Validation;
  const visit = (n: ts.Node): void => {
    if (t.isTypeOfExpression(n)) result = best(result, 'full');
    if (t.isBinaryExpression(n)) {
      const k = n.operatorToken.kind;
      if (k === t.SyntaxKind.InstanceOfKeyword || k === t.SyntaxKind.InKeyword) result = best(result, 'full');
      if ((k === t.SyntaxKind.EqualsEqualsEqualsToken || k === t.SyntaxKind.ExclamationEqualsEqualsToken)
        && ['type', 'kind', 'action', 'event', 'cmd', 'command', 'name'].includes(memberName(ctx, n.left) ?? '')
        && t.isStringLiteralLike(strip(ctx, n.right))) result = best(result, 'discriminant');
    }
    if (t.isCallExpression(n)) {
      const name = memberName(ctx, n.expression) ?? (t.isIdentifier(n.expression) ? n.expression.text : '');
      if (['isArray', 'safeParse', 'parse', 'validate', 'validateSync', 'is', 'isInteger', 'isFinite', 'isSafeInteger'].includes(name)) result = best(result, 'full');
      const decl = ctx.symbols.callee(n)?.declaration;
      if (decl?.type && t.isTypePredicateNode(decl.type)) result = best(result, 'predicate');
    }
    if (t.isPropertyAccessExpression(n) && n.name.text === 'success') result = best(result, 'full');
    t.forEachChild(n, visit);
  };
  visit(cond);
  return result;
}

const VALIDATING_STEP = /unmodeled call (parse|safeParse|validate|validateSync|decode|assert\w*|cast)\(\)/;

export const ngb009 = defineRule({
  meta: {
    id: 'NGB009',
    name: 'Unvalidated message payload',
    category: 'cross-window',
    defaultSeverity: 'high',
    cwe: ['CWE-20', 'CWE-940'],
    docs: {
      description:
        "Traces `MessageEvent.data` from window message handlers into security-relevant operations (DOM HTML sinks, navigation, `eval`, Web Storage writes, HttpClient / fetch requests, Router navigation, Renderer2 property writes, trust-bypass APIs) and reports flows that are not preceded by runtime validation of the payload.",
      rationale:
        'TypeScript types such as `(e: MessageEvent<Command>)` or `e.data as Command` are erased at runtime; the payload is whatever the sender posted. Without structural validation, unexpected types and fields reach sensitive code — even from an allowed origin that is itself compromised or buggy.',
      patterns: [
        'Data flow from `event.data` (typed `MessageEvent`, destructured `{ data }`) through variables, helpers and services (taint engine) to the operations listed above',
        'Full validation: `typeof` / `instanceof` / `in` checks, `Array.isArray`, schema calls such as `schema.parse()` / `safeParse()` / `validate()` (in a dominating guard or on the data path)',
        'User type-predicate functions (`function isCommand(x): x is Command`) are recognized, but reported with low confidence because their body is not verified',
        "Discriminant-only checks (`data.type === 'resize'`) do not validate the rest of the payload: reported with medium confidence",
        'A strict origin check (see NGB007) lowers confidence to low',
      ],
      limitations: [
        'Only handlers on `window` are considered (not MessagePort/Worker/BroadcastChannel).',
        'Validation must be a guard on the flow (same function as the source or sink) or a call on the data path; validation stored in a flag variable is not recognized.',
        'The handler parameter must be typed `MessageEvent` or be inferred as one (e.g. inline `addEventListener` callbacks); `any`-typed events are not recognized as sources.',
      ],
      falsePositives: [
        'Libraries that validate internally (e.g. a typed RPC layer) are not recognized unless the call appears as a validation guard.',
      ],
      remediation:
        'Validate the full message shape at runtime before acting on it — with a schema library (zod, valibot, ajv) or explicit `typeof`/`in` checks — and only then read fields. Combine with origin (NGB007) and source (NGB008) checks.',
      example: {
        unsafe: `window.addEventListener('message', (e: MessageEvent<{ url: string }>) => {
  if (e.origin !== PARTNER) return;
  location.href = e.data.url;
});`,
        safe: `const Msg = z.object({ url: z.string().url().startsWith('https://partner.example.com/') });
window.addEventListener('message', (e) => {
  if (e.origin !== PARTNER) return;
  const parsed = Msg.safeParse(e.data);
  if (parsed.success) location.href = parsed.data.url;
});`,
      },
      references: [{ title: 'OWASP HTML5 Security — Web Messaging', url: 'https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html#web-messaging' }],
    },
  },
  analyze(ctx) {
    const handlers = findMessageHandlers(ctx);
    if (!handlers.length) return [];
    const scopeOwner = new Map<ts.Node, MessageHandler>();
    for (const h of handlers) for (const s of handlerScopes(ctx, h)) scopeOwner.set(s.fn, h);
    const ownerOf = (n: ts.Node) => {
      for (let p: ts.Node | undefined = n; p; p = p.parent) {
        const h = scopeOwner.get(p);
        if (h) return h;
      }
      return undefined;
    };

    const findings: RuleFinding[] = [];
    for (const op of sensitiveOperations(ctx)) {
      let chosen: { flow: TaintFlow; validation: Validation; originStrict: boolean; h: MessageHandler } | undefined;
      for (const value of op.values) {
        for (const flow of ctx.taint.trace(value).flows) {
          if (flow.source.kind !== 'message') continue;
          const h = ownerOf(flow.source.node);
          if (!h) continue;
          let validation: Validation;
          for (const g of [...ctx.flow.guards(flow.source.node), ...ctx.flow.guards(op.node)]) validation = best(validation, classifyValidation(ctx, g.condition));
          if (flow.steps.some((s) => VALIDATING_STEP.test(s.description))) validation = 'full';
          if (validation === 'full') continue;
          const originStrict = readCheck(ctx, h, { node: flow.source.node, via: [] }, 'origin') === 'strict';
          if (!chosen || rank(validation) < rank(chosen.validation)) chosen = { flow, validation, originStrict, h };
        }
      }
      if (!chosen) continue;
      const { flow, validation, originStrict } = chosen;
      let confidence: Confidence = validation === 'predicate' ? 'low' : validation === 'discriminant' ? 'medium' : 'high';
      if (originStrict) confidence = 'low';
      confidence = minConfidence(confidence, flow.confidence);
      findings.push({
        node: op.node,
        message: validation === 'discriminant'
          ? `Message data reaches ${op.label} after only a discriminant check (e.g. data.type === '…'); the remaining fields are not validated.`
          : validation === 'predicate'
            ? `Message data reaches ${op.label} after a custom type-predicate check whose runtime behaviour was not verified.`
            : `Message data reaches ${op.label} without runtime validation of the payload.`,
        confidence,
        evidenceKind: 'dataflow',
        trace: [...flow.steps, sinkStep(ctx, op.node, op.label)],
        evidence: [
          ...flowEvidence(flow),
          `handler registered via ${chosen.h.how}`,
          originStrict ? 'a strict origin check guards the handler (lower risk)' : 'no strict origin check guards this flow',
        ],
      });
    }
    return findings;
  },
});
