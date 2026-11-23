import { defineRule, type RuleFinding } from '@ngbastion/plugin-api';
import { constantPrefix, is, isGlobalCall, receiverOf, strip } from '../shared/common.js';

const SAME_WINDOW = new Set(['_self', '_parent', '_top']);

export const ngb033 = defineRule({
  meta: {
    id: 'NGB033',
    name: 'window.open() without noopener',
    category: 'cross-window',
    defaultSeverity: 'low',
    cwe: ['CWE-1022'],
    docs: {
      description:
        "Reports `window.open(url)` calls that open another site (an absolute external URL or a dynamic URL) in a new browsing context without `noopener` or `noreferrer` in the features argument, when the returned window handle is not used. The opened page then receives `window.opener` and can navigate your tab.",
      rationale:
        "Unlike `<a target=\"_blank\">` (which browsers now treat as `noopener`), `window.open()` still gives the new page a reference to your window. A malicious or compromised destination can run `window.opener.location = 'https://phish.example/login'` and replace your application with a look-alike while the user is reading the other tab (reverse tabnabbing).",
      patterns: [
        '`window.open(url)`, `window.open(url, "_blank")`, `open(url, name, "width=600")` resolved to the DOM `Window.open`',
        'Reported when the URL is dynamic or an absolute `http(s)://` URL, the target is not `_self` / `_parent` / `_top`, the features do not contain `noopener` / `noreferrer`, and the return value is discarded',
        'Relative same-origin URLs (`/help`) are not reported',
      ],
      limitations: [
        'Popups whose handle is kept (e.g. OAuth or payment popups that use `postMessage`) need the opener and are not reported.',
        'Dynamic feature strings are treated as not containing `noopener`.',
      ],
      falsePositives: [
        'A dynamic URL that always points to your own origin is reported; the impact is nil in that case.',
      ],
      remediation:
        "Pass `noopener,noreferrer`: `window.open(url, '_blank', 'noopener,noreferrer')`, or set `popup.opener = null` immediately when you need the handle.",
      example: {
        unsafe: `window.open(this.partnerUrl, '_blank');`,
        safe: `window.open(this.partnerUrl, '_blank', 'noopener,noreferrer');`,
      },
      references: [
        { title: 'MDN — window.open() noopener', url: 'https://developer.mozilla.org/docs/Web/API/Window/open#noopener' },
        { title: 'OWASP — Reverse Tabnabbing', url: 'https://owasp.org/www-community/attacks/Reverse_Tabnabbing' },
      ],
    },
  },
  analyze(ctx) {
    const t = ctx.ts;
    const findings: RuleFinding[] = [];
    for (const call of ctx.index.calls) {
      const info = ctx.symbols.callee(call);
      if (!info || info.name !== 'open' || info.declaration || !call.arguments[0]) continue;
      const recv = receiverOf(ctx, strip(ctx, call.expression));
      if (!(recv ? is(info.receiver, 'dom', 'Window') : isGlobalCall(info, 'open'))) continue;
      // Return value used → the caller needs the handle (popup flows).
      let p = call.parent;
      while (t.isParenthesizedExpression(p) || t.isAsExpression(p)) p = p.parent;
      if (!t.isExpressionStatement(p) && !(t.isVoidExpression(p))) continue;
      const target = call.arguments[1] ? ctx.symbols.constantString(call.arguments[1]) : '_blank';
      if (target !== undefined && SAME_WINDOW.has(target.toLowerCase())) continue;
      const features = call.arguments[2] ? ctx.symbols.constantString(call.arguments[2]) : '';
      if (features !== undefined && /\bno(opener|referrer)\b/i.test(features)) continue;
      const url = ctx.symbols.constantString(call.arguments[0]);
      const prefix = constantPrefix(ctx, call.arguments[0]);
      if (url !== undefined && !/^\s*(https?:)?\/\//i.test(url)) continue;
      if (url === undefined && prefix && /^\/(?![/\\])/.test(prefix)) continue;
      findings.push({
        node: call,
        message: `window.open() opens ${url ? `'${url}'` : 'a dynamic URL'} without noopener; the opened page can control this tab through window.opener (reverse tabnabbing).`,
        confidence: url ? 'high' : 'medium',
        evidenceKind: 'pattern',
        evidence: [`features: ${features === undefined ? 'dynamic' : features ? JSON.stringify(features) : '(none)'}`, 'return value discarded'],
      });
    }
    return findings;
  },
});
