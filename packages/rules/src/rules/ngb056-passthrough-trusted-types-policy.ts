import type * as ts from 'typescript';
import { defineRule, type AnalysisContext, type RuleFinding } from '@ngbastion/plugin-api';
import { memberName, receiverOf, strip } from '../shared/common.js';
import { isParam, returns } from '../shared/functions.js';
import { objectLiteral } from '../shared/http.js';

const FACTORIES: Record<string, string> = { createHTML: 'TrustedHTML', createScript: 'TrustedScript', createScriptURL: 'TrustedScriptURL' };

/** `trustedTypes`, `window.trustedTypes`, `self.trustedTypes`, `globalThis.trustedTypes` (also via casts). */
function isTrustedTypesFactory(ctx: AnalysisContext, e: ts.Expression): boolean {
  const t = ctx.ts;
  const x = strip(ctx, e);
  if (t.isIdentifier(x)) {
    const d = ctx.symbols.declarationOf(x);
    return x.text === 'trustedTypes' && (!d || d.getSourceFile().isDeclarationFile || !!(t.getCombinedModifierFlags(d) & t.ModifierFlags.Ambient));
  }
  if (memberName(ctx, x) !== 'trustedTypes') return false;
  const recv = receiverOf(ctx, x);
  return !!recv && /^(window|self|globalThis)$/.test(strip(ctx, recv).getText());
}

/** The function contains a decision (branch, throw, validation call) before returning its input. */
function hasCheck(ctx: AnalysisContext, fn: ts.SignatureDeclaration): boolean {
  const t = ctx.ts;
  let found = false;
  const visit = (n: ts.Node): void => {
    if (found || (n !== fn && t.isFunctionLike(n))) return;
    if (t.isIfStatement(n) || t.isConditionalExpression(n) || t.isThrowStatement(n) || t.isSwitchStatement(n)) found = true;
    if (t.isBinaryExpression(n) && [t.SyntaxKind.AmpersandAmpersandToken, t.SyntaxKind.BarBarToken, t.SyntaxKind.QuestionQuestionToken].includes(n.operatorToken.kind)) found = true;
    t.forEachChild(n, visit);
  };
  visit(fn);
  return found;
}

export const ngb056 = defineRule({
  meta: {
    id: 'NGB056',
    name: 'Pass-through Trusted Types policy',
    category: 'angular-xss',
    defaultSeverity: 'high',
    cwe: ['CWE-79', 'CWE-116'],
    docs: {
      description:
        "Reports Trusted Types policies created with `trustedTypes.createPolicy()` whose `createHTML`, `createScript` or `createScriptURL` returns its input unchanged without any check. A pass-through `default` policy is high severity (it silently approves every string assigned to any DOM sink); named pass-through policies are medium.",
      rationale:
        "Trusted Types (enforced through `require-trusted-types-for 'script'`, which Angular supports) is only as strong as the policies the application defines. A policy `createHTML: (s) => s` converts any string — including attacker-controlled HTML — into `TrustedHTML`, so the CSP header still claims protection while DOM XSS works as before. A pass-through `default` policy disables enforcement for the whole page.",
      patterns: [
        "`trustedTypes.createPolicy(name, { createHTML: (s) => s })` (also `window.` / `self.` / `globalThis.trustedTypes`, method or function-expression members, `String(s)`, `s as string`)",
        'Not reported: policies that sanitize (`DOMPurify.sanitize(s)`), or contain any branch / throw / validation before returning the input (e.g. an origin allowlist in `createScriptURL`)',
        "Policy name `'default'` → high, other names → medium",
      ],
      limitations: [
        'Policies defined in libraries (e.g. DOMPurify, Angular) are not inspected.',
        'The quality of validation in a policy is not assessed: any branch counts as a check.',
      ],
      falsePositives: [
        "Named pass-through policies that are only ever applied to constant strings are safe in practice; restrict them with the `trusted-types` CSP directive and document an exception.",
      ],
      remediation:
        "Sanitize in `createHTML` (`DOMPurify.sanitize(s, { RETURN_TRUSTED_TYPE: true })`), validate script URLs against an origin allowlist and throw otherwise, and avoid `createScript`. Do not define a `default` policy unless it rejects or sanitizes, and limit allowed policy names with the CSP `trusted-types` directive.",
      example: {
        unsafe: `trustedTypes.createPolicy('default', { createHTML: (s) => s, createScriptURL: (s) => s });`,
        safe: `trustedTypes.createPolicy('app-html', { createHTML: (s) => DOMPurify.sanitize(s) });
trustedTypes.createPolicy('app-scripts', { createScriptURL: (s) => { if (new URL(s, location.href).origin !== location.origin) throw new TypeError('blocked'); return s; } });`,
      },
      references: [
        { title: 'web.dev — Prevent DOM-based XSS with Trusted Types', url: 'https://web.dev/articles/trusted-types' },
        { title: 'Angular — Enforcing Trusted Types', url: 'https://angular.dev/best-practices/security#enforcing-trusted-types' },
        { title: 'W3C — Trusted Types: default policy', url: 'https://w3c.github.io/trusted-types/dist/spec/#default-policy-hdr' },
      ],
    },
  },
  analyze(ctx) {
    const t = ctx.ts;
    const findings: RuleFinding[] = [];
    for (const call of ctx.index.calls) {
      if (memberName(ctx, call.expression) !== 'createPolicy') continue;
      const recv = receiverOf(ctx, call.expression);
      if (!recv || !isTrustedTypesFactory(ctx, recv)) continue;
      const name = call.arguments[0] ? ctx.symbols.constantString(call.arguments[0]) : undefined;
      const obj = objectLiteral(ctx, call.arguments[1]);
      if (!obj) continue;
      for (const p of obj.properties) {
        const key = p.name && (t.isIdentifier(p.name) || t.isStringLiteralLike(p.name)) ? p.name.text : undefined;
        if (!key || !Object.hasOwn(FACTORIES, key)) continue;
        let fn: ts.SignatureDeclaration | undefined;
        if (t.isMethodDeclaration(p)) fn = p;
        else if (t.isPropertyAssignment(p)) fn = ctx.flow.resolveFunction(p.initializer);
        else if (t.isShorthandPropertyAssignment(p)) fn = ctx.flow.resolveFunction(p.name);
        const input = fn?.parameters[0];
        if (!fn || !input) continue;
        const rets = returns(ctx, fn);
        if (!rets.length || !rets.every((r) => isParam(ctx, r, input)) || hasCheck(ctx, fn)) continue;
        const isDefault = name === 'default';
        findings.push({
          node: p,
          message: `Trusted Types policy '${name ?? '(dynamic name)'}' ${key}() returns its input unchanged: any string becomes ${FACTORIES[key]}${isDefault ? ' for every DOM sink on the page' : ''}, defeating Trusted Types.`,
          confidence: 'high',
          severity: isDefault ? 'high' : 'medium',
          evidenceKind: 'pattern',
          evidence: [`policy name: ${name ?? '(dynamic)'}`, `${key}: returns its argument without sanitization or validation`],
        });
      }
    }
    return findings;
  },
});
