import type * as ts from 'typescript';
import { defineRule, type AnalysisContext, type RuleFinding } from '@ngbastion/plugin-api';
import { is, memberName, receiverOf, strip } from '../shared/common.js';
import { sensitiveValue } from '../shared/sensitivity.js';

/** `window`, `globalThis`, `self` (typed Window or the bare global names). */
export function isGlobalObject(ctx: AnalysisContext, e: ts.Expression): boolean {
  const x = strip(ctx, e);
  if (ctx.ts.isIdentifier(x) && ['window', 'globalThis', 'self'].includes(x.text)) {
    const d = ctx.symbols.declarationOf(x);
    return !d || d.getSourceFile().isDeclarationFile;
  }
  return is(ctx.symbols.typeOrigin(x), 'dom', 'Window');
}

/** Properties of Window that are not plain global variables. */
const WINDOW_API = new Set(['name', 'location', 'status', 'opener', 'onmessage', 'onload', 'onerror', 'onbeforeunload', 'document', 'origin']);

export const ngb028 = defineRule({
  meta: {
    id: 'NGB028',
    name: 'Sensitive data on global objects',
    category: 'sensitive-data',
    defaultSeverity: 'medium',
    cwe: ['CWE-200', 'CWE-922'],
    docs: {
      description:
        'Reports credentials and payment data assigned to properties of the global object — `window.authToken = …`, `(window as any).__SESSION__ = …`, `globalThis.apiKey = …`, `window["cardNumber"] = …` — and passed to `Object.defineProperty(window, …)`. Evidence comes from the property name and the value (name, type, data flow).',
      rationale:
        'Global properties are readable by every script in the page — analytics, tag managers, chat widgets, browser extensions and any XSS payload — without needing access to your modules. Keeping secrets in module scope or injectable services at least requires an attacker to find them; globals are one `Object.keys(window)` away and frequently end up in error reports.',
      patterns: [
        '`window.x = v`, `globalThis.x = v`, `self.x = v`, `window["x"] = v`, `(window as any).x = v`',
        '`Object.defineProperty(window, "x", { value: v })`',
        'Sensitive when the property name or the value is classified as a credential (`accessToken`, `jwt`, `apiKey`, `password`, `sessionId`) or payment data (`cardNumber`, `cvv`)',
        '`window.name` is handled by NGB029; DOM APIs (`location`, `opener`, event handlers) are ignored',
      ],
      limitations: [
        'Globals created through `declare global` + plain `var` declarations in scripts outside the Angular build are not seen.',
        'Assignments through aliases (`const w: any = window; w.token = …`) are covered only when the alias is typed as `Window`.',
      ],
      falsePositives: [
        'Public configuration intentionally exposed on `window` (e.g. a publishable key) can be reported when its name looks like a credential.',
      ],
      remediation:
        'Keep tokens in an injectable service (in memory) and pass them only to the code that needs them. If a legacy script needs a value, hand it over through a narrow function call instead of a global property.',
      example: {
        unsafe: `(window as any).__AUTH__ = { accessToken: res.access_token };`,
        safe: `this.session.setAccessToken(res.access_token); // AuthService keeps it in a private field`,
      },
      references: [{ title: 'OWASP — HTML5 Security Cheat Sheet (global variables)', url: 'https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html' }],
    },
  },
  analyze(ctx) {
    const t = ctx.ts;
    const findings: RuleFinding[] = [];
    const check = (node: ts.Node, key: string | undefined, value: ts.Expression, how: string) => {
      if (key && WINDOW_API.has(key)) return;
      const s = sensitiveValue(ctx, value, { keys: [key] });
      if (!s) return;
      findings.push({
        node,
        message: `${s.category === 'payment' ? 'Payment data' : 'A credential'} is stored on the global object (${how}); every script in the page, including third-party and injected code, can read it.`,
        confidence: s.confidence,
        evidenceKind: 'heuristic',
        evidence: s.evidence,
        redactSnippet: true,
      });
    };
    for (const a of ctx.index.assignments) {
      if (a.operatorToken.kind !== t.SyntaxKind.EqualsToken) continue;
      const left = strip(ctx, a.left);
      const recv = receiverOf(ctx, left);
      if (!recv || !isGlobalObject(ctx, recv)) continue;
      const key = memberName(ctx, left) ?? (t.isElementAccessExpression(left) ? ctx.symbols.constantString(left.argumentExpression) : undefined);
      check(a, key, a.right, `${strip(ctx, recv).getText()}.${key ?? '[…]'}`);
    }
    for (const call of ctx.index.calls) {
      const callee = strip(ctx, call.expression);
      if (callee.getText() !== 'Object.defineProperty' || !call.arguments[2] || !isGlobalObject(ctx, call.arguments[0]!)) continue;
      const desc = strip(ctx, call.arguments[2]);
      const v = t.isObjectLiteralExpression(desc) ? desc.properties.find((p): p is ts.PropertyAssignment => t.isPropertyAssignment(p) && p.name.getText() === 'value') : undefined;
      if (v) check(call, ctx.symbols.constantString(call.arguments[1]!), v.initializer, 'Object.defineProperty(window, …)');
    }
    return findings;
  },
});
