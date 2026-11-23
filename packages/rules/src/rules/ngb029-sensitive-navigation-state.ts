import type * as ts from 'typescript';
import { defineRule, type RuleFinding, type Severity } from '@ngbastion/plugin-api';
import { is, memberName, receiverOf, strip } from '../shared/common.js';
import { objectProp } from '../shared/http.js';
import { sensitiveValue } from '../shared/sensitivity.js';
import { isGlobalObject } from './ngb028-sensitive-global-objects.js';

export const ngb029 = defineRule({
  meta: {
    id: 'NGB029',
    name: 'Sensitive data in navigation state',
    category: 'sensitive-data',
    defaultSeverity: 'high',
    cwe: ['CWE-200', 'CWE-922'],
    docs: {
      description:
        'Reports credentials and payment data written to browser navigation state: `window.name` (high severity — it survives cross-origin navigation), `history.pushState()` / `replaceState()` state objects, and Angular Router navigation state (`router.navigate(…, { state })`, `navigateByUrl(…, { state })`), which is stored in `history.state`.',
      rationale:
        '`window.name` belongs to the browsing context, not the origin: after the user navigates to (or is redirected to) another site, that site can read the value. History state is persisted by the browser for back/forward navigation and session restore, outlives logout within the tab, and is readable by any script on your origin.',
      patterns: [
        '`window.name = v`, `self.name = v`, `globalThis.name = v`',
        '`history.pushState(state, …)`, `history.replaceState(state, …)` on the DOM `History`',
        '`router.navigate(commands, { state: {…} })`, `router.navigateByUrl(url, { state: {…} })` (`Router` from `@angular/router`)',
        'Sensitivity: names, declared types and data-flow names classified as credentials or payment data (see NGB014/NGB016)',
      ],
      limitations: [
        'Angular `Location.go(path, query, state)` and third-party routers are not covered.',
        'State objects built in another function are classified by their names/types only.',
      ],
      falsePositives: [
        'Opaque identifiers with credential-like names (`resetTokenId`) can be reported.',
      ],
      remediation:
        'Pass secrets between views through an in-memory service, not through navigation state. Never use `window.name` as a transport; clear it (`window.name = ""`) if a legacy flow used it.',
      example: {
        unsafe: `this.router.navigate(['/checkout/confirm'], { state: { cardNumber: form.cardNumber, cvv: form.cvv } });`,
        safe: `this.checkout.setPending(form); // CheckoutService keeps it in memory
this.router.navigate(['/checkout/confirm']);`,
      },
      references: [
        { title: 'MDN — Window.name', url: 'https://developer.mozilla.org/docs/Web/API/Window/name' },
        { title: 'MDN — History.pushState()', url: 'https://developer.mozilla.org/docs/Web/API/History/pushState' },
      ],
    },
  },
  analyze(ctx) {
    const t = ctx.ts;
    const findings: RuleFinding[] = [];
    const check = (node: ts.Node, value: ts.Expression, where: string, severity: Severity, why: string) => {
      const s = sensitiveValue(ctx, value);
      if (!s) return;
      findings.push({
        node,
        message: `${s.category === 'payment' ? 'Payment data' : 'A credential'} is written to ${where}; ${why}`,
        confidence: s.confidence,
        severity,
        evidenceKind: 'heuristic',
        evidence: s.evidence,
        redactSnippet: true,
      });
    };
    for (const a of ctx.index.assignments) {
      const left = strip(ctx, a.left);
      const recv = receiverOf(ctx, left);
      if (a.operatorToken.kind === t.SyntaxKind.EqualsToken && memberName(ctx, left) === 'name' && recv && isGlobalObject(ctx, recv)) {
        check(a, a.right, 'window.name', 'high', 'the value stays readable by any site this tab navigates to.');
      }
    }
    for (const call of ctx.index.calls) {
      const info = ctx.symbols.callee(call);
      if (!info || info.declaration) continue;
      if ((info.name === 'pushState' || info.name === 'replaceState') && is(info.receiver, 'dom', 'History') && call.arguments[0]) {
        check(call, call.arguments[0], `history.${info.name}() state`, 'medium', 'the browser keeps it in session history, readable by any script on the origin and restored after reloads.');
      } else if ((info.name === 'navigate' || info.name === 'navigateByUrl') && is(info.receiver, '@angular/router', 'Router') && call.arguments[1]) {
        const state = objectProp(ctx, call.arguments[1], 'state');
        if (state) check(call, state, `Router.${info.name}() navigation state (history.state)`, 'medium', 'the browser keeps it in session history, readable by any script on the origin and restored after reloads.');
      }
    }
    return findings;
  },
});
