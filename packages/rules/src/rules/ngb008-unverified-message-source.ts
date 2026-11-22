import type * as ts from 'typescript';
import { defineRule, type RuleFinding } from '@ngbastion/plugin-api';
import { enclosingClass, memberName, receiverOf, strip } from '../shared/common.js';
import { findMessageHandlers, messageReads, readCheck, referencesProp } from '../shared/messages.js';

/** Expressions that denote a specific peer window the code communicates with. */
function peerWindowRefs(ctx: Parameters<typeof findMessageHandlers>[0], scope: ts.Node): string[] {
  const t = ctx.ts;
  const refs = new Set<string>();
  const visit = (n: ts.Node): void => {
    if (t.isPropertyAccessExpression(n) && (n.name.text === 'contentWindow' || n.name.text === 'opener')) refs.add(`.${n.name.text}`);
    if (t.isCallExpression(n)) {
      const callee = strip(ctx, n.expression);
      const name = memberName(ctx, callee);
      const recv = receiverOf(ctx, callee);
      if (name === 'open' && recv && /^(window|globalThis|self)$/.test(strip(ctx, recv).getText())) refs.add('window.open()');
      if (name === 'postMessage' && recv && /^(window\.)?(parent|top)$/.test(strip(ctx, recv).getText())) refs.add(`${strip(ctx, recv).getText()}.postMessage()`);
    }
    t.forEachChild(n, visit);
  };
  visit(scope);
  return [...refs];
}

export const ngb008 = defineRule({
  meta: {
    id: 'NGB008',
    name: 'Unverified message source',
    category: 'cross-window',
    defaultSeverity: 'medium',
    cwe: ['CWE-346'],
    docs: {
      description:
        'Reports message handlers that never compare `event.source` with the window they communicate with, but only where such a specific peer exists in the same class (or file, for code outside classes): an iframe `contentWindow`, a popup from `window.open()`, `window.opener`, or `window.parent`/`window.top` used with `postMessage`.',
      rationale:
        'An origin check proves which site sent a message, not which window. Several frames or popups can share an origin (e.g. two instances of the same widget, or an attacker-controlled page on a shared hosting origin), so a handler that expects replies from one particular frame should also verify `event.source === frame.contentWindow`.',
      patterns: [
        'Peer windows: `iframe.contentWindow`, `this.frame.nativeElement.contentWindow`, `window.open(...)`, `window.opener`, `window.parent.postMessage(...)`, `window.top.postMessage(...)`',
        "Handlers discovered like NGB007 (`addEventListener('message')`, `@HostListener('window:message')`, host bindings, `fromEvent`, `Renderer2.listen`)",
        "Accepted verification: `event.source === peer` / `!==` with early return, including checks in `fromEvent(...).pipe(filter(...))`",
      ],
      limitations: [
        'Only peers referenced in the same class (or same file outside classes) as the handler are considered.',
        'The compared value is not verified to be the same peer window; any equality check on `event.source` is accepted.',
      ],
      falsePositives: [
        'Handlers that only process messages from one origin that can host exactly one frame may not need a source check; suppress with a justification.',
      ],
      remediation:
        'Keep a reference to the peer window and ignore other senders: `if (event.source !== this.frame.nativeElement.contentWindow) return;` — in addition to the origin check.',
      example: {
        unsafe: `@HostListener('window:message', ['$event'])
onMessage(e: MessageEvent) {
  if (e.origin !== WIDGET_ORIGIN) return;
  this.height = e.data.height;
}`,
        safe: `@HostListener('window:message', ['$event'])
onMessage(e: MessageEvent) {
  if (e.origin !== WIDGET_ORIGIN || e.source !== this.frame.nativeElement.contentWindow) return;
  this.height = e.data.height;
}`,
      },
      references: [{ title: 'MDN — MessageEvent.source', url: 'https://developer.mozilla.org/docs/Web/API/MessageEvent/source' }],
    },
  },
  analyze(ctx) {
    const findings: RuleFinding[] = [];
    for (const h of findMessageHandlers(ctx)) {
      const reads = messageReads(ctx, h);
      if (!reads.length) continue;
      const scope: ts.Node = enclosingClass(ctx, h.fn) ?? h.fn.getSourceFile();
      const peers = peerWindowRefs(ctx, scope);
      if (!peers.length) continue;
      if (reads.every((r) => readCheck(ctx, h, r, 'source') === 'strict')) continue;
      const referenced = referencesProp(ctx, h, 'source');
      findings.push({
        node: h.registration,
        message: referenced
          ? 'Message handler reads event.source but does not use it to guard message processing; messages from other windows of the same origin are accepted.'
          : 'Message handler communicates with a specific window but never verifies event.source; any window sharing the allowed origin can send it messages.',
        confidence: 'medium',
        evidenceKind: 'pattern',
        evidence: [`peer window reference(s) in scope: ${peers.join(', ')}`, `handler registered via ${h.how}`],
      });
    }
    return findings;
  },
});
