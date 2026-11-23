import type * as ts from 'typescript';
import { defineRule, type RuleFinding } from '@ngbastion/plugin-api';
import { is, strip } from '../shared/common.js';
import { classifyName, sensitiveValue } from '../shared/sensitivity.js';

export const ngb066 = defineRule({
  meta: {
    id: 'NGB066',
    name: 'Sensitive data copied to the clipboard',
    category: 'sensitive-data',
    defaultSeverity: 'low',
    cwe: ['CWE-200', 'CWE-359'],
    docs: {
      description:
        "Reports credentials and payment data (passwords, access / refresh tokens, API keys, card numbers, CVV) written to the system clipboard with `navigator.clipboard.writeText()` / `write()`, the Angular CDK `Clipboard.copy()` / `beginCopy()` service, or the `[cdkCopyToClipboard]` template directive. Sensitivity comes from the value's name, its type, names along its data flow or a card-number literal; masked or hashed values are ignored.",
      rationale:
        "The clipboard is shared with every application on the device and often synced: clipboard managers keep a history, remote-desktop and cloud-clipboard features copy it to other machines, mobile keyboards read it, and any later paste lands the secret in chats or tickets. Copying a bearer token or card number turns a protected value into one with no access control or expiry.",
      patterns: [
        '`navigator.clipboard.writeText(v)` / `navigator.clipboard.write(items)` on the DOM `Clipboard`',
        "`clipboard.copy(v)` / `clipboard.beginCopy(v)` on `Clipboard` from `@angular/cdk/clipboard`",
        '`<button [cdkCopyToClipboard]="accessToken">` in templates (bound expression named like a credential or payment value)',
      ],
      limitations: [
        'Values copied with `document.execCommand("copy")` from a selected element are not traced.',
        'Sensitivity is name- and type-based; secrets with neutral names are not recognized.',
      ],
      falsePositives: [
        'Password managers and API-key settings pages copy secrets on purpose when the user clicks "copy"; keep the finding as a reminder to clear the clipboard after a timeout or document an exception.',
      ],
      remediation:
        'Avoid copying secrets. When copying is a product requirement (password managers, one-time API key display), copy only on an explicit user action, clear the clipboard after a short timeout, and never copy long-lived tokens or full card data.',
      example: {
        unsafe: `copyToken() { navigator.clipboard.writeText(this.auth.accessToken); }`,
        safe: `copyReference() { navigator.clipboard.writeText(this.order.reference); }`,
      },
      references: [
        { title: 'MDN — Clipboard.writeText()', url: 'https://developer.mozilla.org/docs/Web/API/Clipboard/writeText' },
        { title: 'CWE-200: Exposure of Sensitive Information to an Unauthorized Actor', url: 'https://cwe.mitre.org/data/definitions/200.html' },
      ],
    },
  },
  analyze(ctx) {
    const findings: RuleFinding[] = [];
    const report = (node: ts.Node, value: ts.Expression, api: string) => {
      const s = sensitiveValue(ctx, value);
      if (!s) return;
      findings.push({
        node,
        message: `${api} copies ${s.category === 'payment' ? 'payment data' : 'a credential'} ('${s.strongest.match.term}') to the system clipboard, where other applications, clipboard history and sync can read it.`,
        confidence: s.confidence,
        evidenceKind: s.strongest.via === 'name' ? 'pattern' : 'heuristic',
        evidence: [`sink: ${api}`, ...s.evidence],
      });
    };
    for (const call of ctx.index.calls) {
      const info = ctx.symbols.callee(call);
      const arg = call.arguments[0];
      if (!info || info.declaration || !arg) continue;
      if ((info.name === 'writeText' || info.name === 'write') && is(info.receiver, 'dom', 'Clipboard')) report(call, arg, `navigator.clipboard.${info.name}()`);
      else if ((info.name === 'copy' || info.name === 'beginCopy') && is(info.receiver, '@angular/cdk/clipboard', 'Clipboard')) report(call, arg, `Clipboard.${info.name}() (@angular/cdk)`);
      else if (info.name === 'writeText' && !info.receiver && strip(ctx, call.expression).getText().replace(/\s/g, '') === 'navigator.clipboard.writeText') report(call, arg, 'navigator.clipboard.writeText()');
    }
    // [cdkCopyToClipboard]="expr": the bound expression is evaluated in the component class.
    for (const tpl of ctx.templates) {
      for (const el of tpl.elements) {
        for (const a of el.attributes) {
          if (!a.bound || a.name !== 'cdkCopyToClipboard') continue;
          const name = a.value.trim().replace(/\(\)$/, '').split('.').pop() ?? '';
          const m = /^[\w$]+$/.test(name) ? classifyName(name) : undefined;
          if (!m || /(masked|redacted|hashed|last4)/i.test(name)) continue;
          findings.push({
            location: a.location,
            message: `[cdkCopyToClipboard] copies ${m.category === 'payment' ? 'payment data' : 'a credential'} ('${m.term}') to the system clipboard.`,
            confidence: m.strength === 'strong' ? 'medium' : 'low',
            evidenceKind: 'heuristic',
            evidence: [`template binding: [cdkCopyToClipboard]="${a.value}"`],
          });
        }
      }
    }
    return findings;
  },
});
