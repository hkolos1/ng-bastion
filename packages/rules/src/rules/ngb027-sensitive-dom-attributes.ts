import type * as ts from 'typescript';
import { defineRule, type Confidence, type RuleFinding } from '@ngbastion/plugin-api';
import { domElement, is, memberName, receiverOf, strip } from '../shared/common.js';
import { classifyName, sensitiveValue, words } from '../shared/sensitivity.js';

/** Attributes that end up in the serialized DOM (and in SSR HTML). `value` only counts on hidden inputs. */
const REFLECTED = /^(data-[\w-]+|aria-[\w-]+|title|alt|name|id|content|placeholder|label|class)$/i;

/** Credential / payment identifiers inside a template expression (`user.accessToken`, `card.cvv | slice:0:3`). */
function sensitiveTemplateNames(expr: string): { term: string; confidence: Confidence }[] {
  const out: { term: string; confidence: Confidence }[] = [];
  const head = expr.split(/\|(?!\|)/)[0]!;
  for (const m of head.matchAll(/[A-Za-z_$][\w$]*/g)) {
    const name = m[0];
    const next = head[m.index! + name.length];
    if (next === '(') continue; // method names (`getToken()`) describe behaviour
    const c = classifyName(name);
    if (c && !words(name).some((w) => ['masked', 'last4', 'hashed', 'redacted'].includes(w))) out.push({ term: name, confidence: c.strength === 'strong' ? 'medium' : 'low' });
  }
  return out;
}

export const ngb027 = defineRule({
  meta: {
    id: 'NGB027',
    name: 'Sensitive data in DOM attributes',
    category: 'sensitive-data',
    defaultSeverity: 'medium',
    cwe: ['CWE-200', 'CWE-312'],
    docs: {
      description:
        'Reports credentials (tokens, passwords, API keys, session IDs) and payment data (card number, CVV) written into DOM attributes: template bindings such as `[attr.data-token]="accessToken"`, `[title]`, `[id]`, hidden inputs `<input type="hidden" [value]="token">`, and code calling `setAttribute()` / `Renderer2.setAttribute()` / `element.dataset.x = …`.',
      rationale:
        'Attributes are part of the serialized document: they appear in SSR HTML, are captured by session-replay and analytics tools, are visible to every script and browser extension through simple DOM queries (`[data-token]`), and survive in saved pages. Secrets that only code needs belong in memory, not in markup.',
      patterns: [
        'Template attribute/property bindings on reflected attributes: `data-*`, `aria-*`, `title`, `alt`, `name`, `id`, `content`, `placeholder`, `label`, `class`',
        '`<input type="hidden" [value]="…">` (hidden form fields)',
        'Expression names classified as credentials or payment data (`accessToken`, `apiKey`, `password`, `sessionId`, `cardNumber`, `cvv`); CSRF tokens, `last4`, `maskedPan` and method calls are ignored',
        '`el.setAttribute(name, v)`, `renderer.setAttribute(el, name, v)`, `el.dataset.key = v` where the value is classified as sensitive (by name, type or data flow)',
      ],
      limitations: [
        'Template expressions are classified by identifier names only (no type information inside templates).',
        'Attributes set by third-party components from their inputs are not followed.',
      ],
      falsePositives: [
        'Opaque, non-secret identifiers with credential-like names (e.g. a public `tokenId` attribute used for testing selectors) can be reported.',
      ],
      remediation:
        'Keep tokens and card data in component or service fields and pass them to code that needs them; never render them into attributes or hidden inputs. For CSRF tokens use Angular\'s XSRF cookie/header mechanism instead of hidden fields.',
      example: {
        unsafe: `<div class="widget" [attr.data-token]="session.accessToken"></div>`,
        safe: `<div class="widget" [attr.data-user]="session.userId"></div>
<!-- the widget obtains the token from AuthService in code -->`,
      },
      references: [{ title: 'OWASP — Sensitive data exposure (client-side)', url: 'https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure' }],
    },
  },
  analyze(ctx) {
    const t = ctx.ts;
    const findings: RuleFinding[] = [];
    for (const tpl of ctx.templates) {
      for (const el of tpl.elements) {
        const hiddenInput = el.name.toLowerCase() === 'input' && el.attributes.some((a) => !a.bound && a.name.toLowerCase() === 'type' && a.value.toLowerCase() === 'hidden');
        for (const a of el.attributes) {
          if (!a.bound) continue;
          if (!REFLECTED.test(a.name) && !(hiddenInput && a.name === 'value')) continue;
          const hits = sensitiveTemplateNames(a.value);
          if (!hits.length) continue;
          const best = hits.find((h) => h.confidence === 'medium') ?? hits[0]!;
          findings.push({
            location: a.location,
            message: `<${el.name}> in ${tpl.component} renders '${best.term}' into the '${a.name}' attribute; it becomes visible in the DOM, SSR HTML and to every script on the page.`,
            confidence: best.confidence,
            evidenceKind: 'heuristic',
            evidence: [`binding [${a.name}]="${a.value}"`, ...hits.map((h) => `sensitive name '${h.term}'`)],
            redactSnippet: true,
          });
        }
      }
    }

    const report = (node: ts.Node, attr: string | undefined, value: ts.Expression, how: string) => {
      if (attr && !REFLECTED.test(attr) && attr !== 'value') return;
      const s = sensitiveValue(ctx, value, { keys: [attr?.replace(/^data-/, '')] });
      if (!s) return;
      findings.push({
        node,
        message: `${how} stores ${s.category === 'payment' ? 'payment data' : 'a credential'} in the${attr ? ` '${attr}'` : ''} DOM attribute, where every script and DOM-capturing tool can read it.`,
        confidence: s.confidence,
        evidenceKind: 'heuristic',
        evidence: s.evidence,
        redactSnippet: true,
      });
    };
    for (const call of ctx.index.calls) {
      const info = ctx.symbols.callee(call);
      if (!info || info.declaration || info.name !== 'setAttribute') continue;
      const recv = receiverOf(ctx, strip(ctx, call.expression));
      if (is(info.receiver, '@angular/core', 'Renderer2') && call.arguments[2]) {
        report(call, ctx.symbols.constantString(call.arguments[1]!)?.toLowerCase(), call.arguments[2], 'Renderer2.setAttribute()');
      } else if (recv && call.arguments[1] && domElement(ctx, recv)) {
        report(call, ctx.symbols.constantString(call.arguments[0]!)?.toLowerCase(), call.arguments[1], 'setAttribute()');
      }
    }
    for (const a of ctx.index.assignments) {
      if (a.operatorToken.kind !== t.SyntaxKind.EqualsToken) continue;
      const left = strip(ctx, a.left);
      const recv = receiverOf(ctx, left);
      if (recv && memberName(ctx, recv) === 'dataset' && (is(ctx.symbols.typeOrigin(recv), 'dom', 'DOMStringMap') || domElement(ctx, receiverOf(ctx, recv)!))) {
        const key = memberName(ctx, left);
        report(a, key ? `data-${key}` : undefined, a.right, 'element.dataset');
      }
    }
    return findings;
  },
});
