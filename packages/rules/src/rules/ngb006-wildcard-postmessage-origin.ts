import type * as ts from 'typescript';
import { defineRule, type RuleFinding } from '@ngbastion/plugin-api';
import { is, memberName, receiverOf, strip } from '../shared/common.js';
import { describeEvidence, isRedacted, sensitivityOf } from '../shared/sensitivity.js';

/** Receivers that are other windows: typed `Window`, or untyped `.contentWindow` / `.opener` / `.parent` / `.top`. */
function isTargetWindow(ctx: Parameters<typeof sensitivityOf>[0], recv: ts.Expression): boolean {
  const o = ctx.symbols.typeOrigin(recv);
  if (o) return is(o, 'dom', 'Window', 'WindowProxy');
  return /(contentWindow|opener|parent|top|window)$/.test(strip(ctx, recv).getText());
}

export const ngb006 = defineRule({
  meta: {
    id: 'NGB006',
    name: 'Wildcard postMessage origin',
    category: 'cross-window',
    defaultSeverity: 'high',
    cwe: ['CWE-201', 'CWE-345'],
    docs: {
      description:
        "Reports `targetWindow.postMessage(message, '*')` (or `{ targetOrigin: '*' }`) to another window. When the payload is identified as a credential or payment value (by name, by its type's properties or along its data flow), the finding is high severity with high/medium confidence; a wildcard with a payload not identified as sensitive is reported as low severity and low confidence.",
      rationale:
        "`'*'` delivers the message to whatever document is currently loaded in the target window. If an attacker can navigate that frame or popup (very common for popups and embeddable frames), they receive the data — tokens, session identifiers or card data leak cross-origin.",
      patterns: [
        "`win.postMessage(data, '*')` where `win` is a `Window` (iframe `contentWindow`, `window.opener`, `window.parent`, `window.open()` result)",
        "`win.postMessage(data, { targetOrigin: '*' })` and wildcard values held in constants (`const ANY = '*'`)",
        'Payload sensitivity: names such as `accessToken`, `password`, `cvv`, `cardNumber` on the payload, its object-literal keys, its declared type properties, or variables/properties it was derived from',
        'Recognized redaction (`mask…()`, `.slice(-4)`, hashing) downgrades the payload to non-sensitive',
      ],
      limitations: [
        '`Worker.postMessage` / `MessagePort.postMessage` are not reported (no target-origin parameter).',
        'Sensitivity is inferred from names and types; secrets in generically named variables (`value`, `payload`) are only detected when their data flow passes through a sensitive name.',
      ],
      falsePositives: [
        'Broadcasting intentionally public, non-sensitive events (resize notifications, analytics pings) to an embedding page with `*` is reported only as low severity / low confidence.',
      ],
      remediation:
        "Always pass the exact expected origin (`win.postMessage(data, 'https://app.example.com')`). For iframes you created, derive it from the URL you loaded (`new URL(src).origin`). Never send credentials to `'*'`.",
      example: {
        unsafe: `this.frame.nativeElement.contentWindow.postMessage({ accessToken: this.auth.token }, '*');`,
        safe: `this.frame.nativeElement.contentWindow.postMessage({ accessToken: this.auth.token }, 'https://widget.example.com');`,
      },
      references: [{ title: 'MDN — Window.postMessage() security concerns', url: 'https://developer.mozilla.org/docs/Web/API/Window/postMessage#security_concerns' }],
    },
  },
  analyze(ctx) {
    const t = ctx.ts;
    const findings: RuleFinding[] = [];
    for (const call of ctx.index.calls) {
      const callee = strip(ctx, call.expression);
      if (memberName(ctx, callee) !== 'postMessage' || call.arguments.length < 2) continue;
      const recv = receiverOf(ctx, callee)!;
      if (ctx.symbols.callee(call)?.declaration || !isTargetWindow(ctx, recv)) continue;
      const target = strip(ctx, call.arguments[1]!);
      let origin = ctx.symbols.constantString(target);
      if (origin === undefined && t.isObjectLiteralExpression(target)) {
        const p = target.properties.find((x): x is ts.PropertyAssignment => t.isPropertyAssignment(x) && x.name.getText() === 'targetOrigin');
        if (p) origin = ctx.symbols.constantString(p.initializer);
      }
      if (origin !== '*') continue;
      const payload = call.arguments[0]!;
      const trace = ctx.taint.trace(payload);
      const evidence = isRedacted(ctx, payload, trace) ? [] : sensitivityOf(ctx, payload, trace);
      if (evidence.length) {
        const strong = evidence.some((e) => e.match.strength === 'strong' && (e.via === 'name' || e.via === 'type' || e.via === 'literal'));
        const kind = evidence[0]!.match.category === 'payment' ? 'payment data' : 'credentials';
        findings.push({
          node: call,
          message: `postMessage() sends ${kind} ('${evidence[0]!.match.term}') with targetOrigin '*'; any document loaded in the target window can read it.`,
          confidence: strong ? 'high' : 'medium',
          evidenceKind: 'pattern',
          evidence: ["targetOrigin is '*'", ...evidence.slice(0, 4).map(describeEvidence)],
        });
      } else {
        findings.push({
          node: call,
          message: "postMessage() uses targetOrigin '*'; the payload was not identified as sensitive, but any document in the target window receives it.",
          confidence: 'low',
          severity: 'low',
          evidenceKind: 'pattern',
          evidence: ["targetOrigin is '*'", 'payload not identified as credential or payment data'],
        });
      }
    }
    return findings;
  },
});
