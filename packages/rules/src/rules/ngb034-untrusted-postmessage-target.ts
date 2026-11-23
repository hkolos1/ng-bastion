import type * as ts from 'typescript';
import { defineRule, type RuleFinding } from '@ngbastion/plugin-api';
import { flowEvidence, is, memberName, receiverOf, sinkStep, strip } from '../shared/common.js';
import { findMessageHandlers, handlerContaining, propMatcher, readCheck } from '../shared/messages.js';
import { sensitiveValue } from '../shared/sensitivity.js';
import { urlValidation, valueNames } from '../shared/url-guards.js';

const ATTACKER = new Set(['url', 'message', 'window-name', 'referrer']);

/** `win.postMessage(msg, origin)` / `win.postMessage(msg, { targetOrigin })` → the origin expression. */
function targetOrigin(ctx: Parameters<typeof findMessageHandlers>[0], call: ts.CallExpression): ts.Expression | undefined {
  const t = ctx.ts;
  const arg = call.arguments[1];
  if (!arg) return undefined;
  const x = strip(ctx, arg);
  if (t.isObjectLiteralExpression(x)) {
    const p = x.properties.find((q): q is ts.PropertyAssignment => t.isPropertyAssignment(q) && q.name.getText() === 'targetOrigin');
    return p?.initializer;
  }
  return arg;
}

export const ngb034 = defineRule({
  meta: {
    id: 'NGB034',
    name: 'Untrusted postMessage target origin',
    category: 'cross-window',
    defaultSeverity: 'high',
    cwe: ['CWE-201', 'CWE-345'],
    docs: {
      description:
        "Reports `postMessage()` calls whose `targetOrigin` is chosen by an attacker: echoed from `event.origin` inside a message handler that does not strictly validate the sender, or traced from URL parameters, `document.referrer`, `window.name` or message data. NGB006 covers the literal `'*'`; this rule covers origins that are effectively wildcards because the other party picks them.",
      rationale:
        "`targetOrigin` is the only thing that stops a message from being delivered to the wrong window. Replying to `event.origin` without checking it, or taking the origin from `?parentOrigin=` / `document.referrer`, lets any page that frames or opens your app receive the reply — including tokens or user data in the payload.",
      patterns: [
        "`event.source.postMessage(reply, event.origin)` and `{ targetOrigin: e.origin }` inside handlers found like NGB007 (addEventListener, onmessage, HostListener, fromEvent, Renderer2.listen) without a strict origin check that dominates the call",
        "`parent.postMessage(data, new URL(document.referrer).origin)`, `window.opener.postMessage(data, params.get('origin'))` (taint engine)",
        'Severity stays high when the payload is a credential or payment value; otherwise the finding is medium severity',
        'Strict origin allowlists (`ALLOWED.includes(origin)`, equality with a constant) suppress the finding',
      ],
      limitations: [
        'Origins stored in fields or services and used later are followed by the taint engine only for modeled sources; a stored `event.origin` from an earlier message is not followed.',
        'The payload is classified by names and types only.',
      ],
      falsePositives: [
        'Public widgets that deliberately answer any embedder with non-sensitive data are reported with medium severity; document an exception.',
      ],
      remediation:
        "Validate the sender first (`if (!ALLOWED_ORIGINS.includes(event.origin)) return;`) and only then reply to `event.origin`, or post to a constant origin. Never read the target origin from the URL or the referrer.",
      example: {
        unsafe: `window.addEventListener('message', (e) => {
  (e.source as Window).postMessage({ token: this.auth.token }, e.origin);
});`,
        safe: `window.addEventListener('message', (e) => {
  if (!ALLOWED_ORIGINS.includes(e.origin)) return;
  (e.source as Window).postMessage({ token: this.auth.token }, e.origin);
});`,
      },
      references: [{ title: 'MDN — postMessage targetOrigin', url: 'https://developer.mozilla.org/docs/Web/API/Window/postMessage#targetorigin' }],
    },
  },
  analyze(ctx) {
    const findings: RuleFinding[] = [];
    const handlers = findMessageHandlers(ctx);
    for (const call of ctx.index.calls) {
      const callee = strip(ctx, call.expression);
      if (memberName(ctx, callee) !== 'postMessage' || !call.arguments[0]) continue;
      const recv = receiverOf(ctx, callee);
      const ro = recv && ctx.symbols.typeOrigin(recv);
      if (ro && ro.module === 'dom' && !is(ro, 'dom', 'Window', 'MessageEventSource')) continue;
      if (ro && ro.module !== 'dom' && ro.name !== 'any') continue;
      const origin = targetOrigin(ctx, call);
      if (!origin) continue;
      const payload = sensitiveValue(ctx, call.arguments[0]);
      const severity = payload ? 'high' : 'medium';
      const h = handlerContaining(ctx, handlers, call);
      if (h && propMatcher(ctx, h, 'origin')(origin)) {
        if (readCheck(ctx, h, { node: call, via: [] }, 'origin') === 'strict') continue;
        findings.push({
          node: call,
          message: `Message handler replies to event.origin without validating the sender first; any page that can message this window receives ${payload ? 'the sensitive payload' : 'the reply'}.`,
          confidence: 'high',
          severity,
          evidenceKind: 'pattern',
          evidence: [`handler registered via ${h.how}`, 'targetOrigin is the sender-controlled event.origin', ...(payload?.evidence ?? [])],
        });
        continue;
      }
      const result = ctx.taint.trace(origin, { context: 'url' });
      const flow = result.flows.find((f) => ATTACKER.has(f.source.kind));
      if (!flow) continue;
      if (urlValidation(ctx, call, valueNames(ctx, origin, result.names)).host === 'strong') continue;
      findings.push({
        node: call,
        message: `postMessage() target origin comes from ${flow.source.description}; an attacker chooses where ${payload ? 'the sensitive payload' : 'the message'} is delivered.`,
        confidence: flow.confidence,
        severity,
        evidenceKind: 'dataflow',
        trace: [...flow.steps, sinkStep(ctx, call, 'postMessage targetOrigin')],
        evidence: [...flowEvidence(flow), ...(payload?.evidence ?? [])],
      });
    }
    return findings;
  },
});
