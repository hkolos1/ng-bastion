import type * as ts from 'typescript';
import { defineRule, type AnalysisContext, type RuleFinding } from '@ngbastion/plugin-api';
import { ANGULAR_SANITIZER_MODULES, importedFrom, is, strip } from '../shared/common.js';
import { objectProp } from '../shared/http.js';
import { isParam, returns } from '../shared/functions.js';

type Verdict = { kind: 'passthrough' | 'partial' | 'custom'; detail: string };

/** Delegation to a real sanitizer: DOMPurify, or Angular's own DomSanitizer instance. */
function delegates(ctx: AnalysisContext, fn: ts.SignatureDeclaration): boolean {
  const t = ctx.ts;
  let found = false;
  const visit = (n: ts.Node): void => {
    if (found) return;
    if (t.isCallExpression(n)) {
      const info = ctx.symbols.callee(n);
      const recvText = t.isPropertyAccessExpression(strip(ctx, n.expression)) ? (strip(ctx, n.expression) as ts.PropertyAccessExpression).expression.getText() : '';
      if (info?.name === 'sanitize' && (['dompurify', 'isomorphic-dompurify'].includes(info.receiver?.module ?? '') || /^DOMPurify$/.test(recvText) || is(info.receiver, ANGULAR_SANITIZER_MODULES, 'DomSanitizer', 'Sanitizer'))) found = true;
      if (info?.name === '_sanitizeHtml' || info?.name === '_sanitizeUrl') found = true;
    }
    t.forEachChild(n, visit);
  };
  visit(fn);
  return found;
}

function assess(ctx: AnalysisContext, fn: ts.SignatureDeclaration): Verdict {
  const value = fn.parameters[1];
  const rets = returns(ctx, fn);
  if (value) {
    const pass = rets.filter((r) => isParam(ctx, r, value));
    if (pass.length && pass.length === rets.length) return { kind: 'passthrough', detail: 'sanitize() returns its input unchanged' };
    if (pass.length) return { kind: 'partial', detail: `sanitize() returns its input unchanged on ${pass.length} of ${rets.length} paths (line ${ctx.location(pass[0]!).line})` };
  }
  if (!rets.length) return { kind: 'passthrough', detail: 'sanitize() returns nothing (every value becomes null)' };
  return { kind: 'custom', detail: 'custom sanitize() implementation' };
}

function sanitizeMember(ctx: AnalysisContext, node: ts.ClassLikeDeclaration | ts.ObjectLiteralExpression): ts.SignatureDeclaration | undefined {
  const t = ctx.ts;
  const members: readonly ts.Node[] = t.isObjectLiteralExpression(node) ? node.properties : node.members;
  for (const m of members) {
    const name = (m as { name?: ts.PropertyName }).name;
    if (!name || !t.isIdentifier(name) || name.text !== 'sanitize') continue;
    if (t.isMethodDeclaration(m)) return m;
    if ((t.isPropertyAssignment(m) || t.isPropertyDeclaration(m)) && m.initializer && (t.isArrowFunction(m.initializer) || t.isFunctionExpression(m.initializer))) return m.initializer;
  }
  return undefined;
}

export const ngb052 = defineRule({
  meta: {
    id: 'NGB052',
    name: 'Unsafe custom Angular sanitizer',
    category: 'angular-xss',
    defaultSeverity: 'high',
    cwe: ['CWE-79', 'CWE-116'],
    docs: {
      description:
        "Reports providers that replace Angular's `Sanitizer` or `DomSanitizer` (`{ provide: Sanitizer, useClass | useValue | useExisting … }`) with an implementation whose `sanitize()` returns its input unchanged (high), does so for some security contexts (high, medium confidence), or contains custom logic that does not delegate to Angular's sanitizer or DOMPurify (medium, low confidence).",
      rationale:
        "Every `[innerHTML]`, `[href]`, `[src]` and `[style]` binding in the application goes through the `Sanitizer` token. Replacing it is a single line that silently disables Angular's XSS protection everywhere — typically added to make a rich-text editor or a legacy widget \"work\". Hand-written sanitizers are also a classic source of bypasses (regex-based tag stripping, allowlists that forget `srcdoc` or `xlink:href`).",
      patterns: [
        '`{ provide: Sanitizer | DomSanitizer, useClass: X }` where `X.sanitize(ctx, value)` returns `value` (also `String(value)`, `value as string`, `value?.toString()`)',
        '`{ provide: Sanitizer, useValue: { sanitize: (_c, v) => v } }`',
        '`useClass` / `useValue` implementations that return the input only under some conditions (`if (ctx === SecurityContext.HTML) return value;`)',
        'Implementations that delegate to `DOMPurify.sanitize()` or an injected Angular `DomSanitizer` are not reported',
      ],
      limitations: [
        'Factories (`useFactory`) and implementations defined in libraries are reported only when the class is visible in the project.',
        'The quality of genuinely custom sanitization logic is not evaluated; such replacements are reported with low confidence for review.',
      ],
      falsePositives: [
        'Test-only providers inside spec files are excluded by the default `exclude` patterns; other test harness modules may be reported.',
      ],
      remediation:
        "Do not replace Angular's sanitizer. Keep the default `DomSanitizer`, sanitize rich text with DOMPurify before binding, and use `bypassSecurityTrust*()` only for specific constant values. If a replacement is unavoidable, delegate to Angular's `ɵDomSanitizerImpl` or DOMPurify for every context.",
      example: {
        unsafe: `@Injectable() class NoopSanitizer extends Sanitizer { sanitize(_ctx: SecurityContext, value: string) { return value; } }
providers: [{ provide: Sanitizer, useClass: NoopSanitizer }]`,
        safe: `providers: [] // keep Angular's DomSanitizer; sanitize rich text with DOMPurify before binding`,
      },
      references: [
        { title: 'Angular — Security: preventing cross-site scripting', url: 'https://angular.dev/best-practices/security#preventing-cross-site-scripting-xss' },
        { title: 'Angular API — Sanitizer', url: 'https://angular.dev/api/core/Sanitizer' },
      ],
    },
  },
  analyze(ctx) {
    const t = ctx.ts;
    const findings: RuleFinding[] = [];
    const visit = (n: ts.Node): void => {
      if (t.isObjectLiteralExpression(n)) check(n);
      t.forEachChild(n, visit);
    };
    const check = (obj: ts.ObjectLiteralExpression) => {
      const provide = objectProp(ctx, obj, 'provide');
      if (!provide) return;
      const token = strip(ctx, provide);
      const origin = ctx.symbols.typeOrigin(token);
      const tokenName = origin && ['Sanitizer', 'DomSanitizer'].includes(origin.name) && ANGULAR_SANITIZER_MODULES.some((m) => origin.module === m || origin.module.startsWith(`${m}/`)) ? origin.name : undefined;
      const imported = ['Sanitizer', 'DomSanitizer'].some((n) => importedFrom(ctx, token, ANGULAR_SANITIZER_MODULES, n));
      if (!tokenName && !imported) return;
      const name = tokenName ?? (token as ts.Identifier).text;

      let impl: ts.ClassLikeDeclaration | ts.ObjectLiteralExpression | undefined;
      const useClass = objectProp(ctx, obj, 'useClass') ?? objectProp(ctx, obj, 'useExisting');
      const useValue = objectProp(ctx, obj, 'useValue');
      if (useClass && t.isIdentifier(strip(ctx, useClass))) {
        const d = ctx.symbols.declarationOf(strip(ctx, useClass));
        if (d && (t.isClassDeclaration(d) || t.isClassExpression(d))) impl = d;
      } else if (useValue) {
        const v = strip(ctx, useValue);
        if (t.isObjectLiteralExpression(v)) impl = v;
        else if (t.isNewExpression(v) && t.isIdentifier(v.expression)) {
          const d = ctx.symbols.declarationOf(v.expression);
          if (d && t.isClassDeclaration(d)) impl = d;
        }
      }
      if (!impl) return;
      const fn = sanitizeMember(ctx, impl);
      if (!fn) return;
      if (delegates(ctx, fn)) return;
      const v = assess(ctx, fn);
      const implName = !t.isObjectLiteralExpression(impl) && impl.name ? impl.name.text : 'an inline object';
      const msg = {
        passthrough: `The ${name} provider is replaced by ${implName}, whose ${v.detail}: Angular's XSS protection is disabled for every binding.`,
        partial: `The ${name} provider is replaced by ${implName}, whose ${v.detail}: those security contexts are not sanitized anywhere in the application.`,
        custom: `The ${name} provider is replaced by a custom implementation (${implName}) that does not delegate to Angular's sanitizer or DOMPurify; review it as the application-wide XSS defence.`,
      }[v.kind];
      findings.push({
        node: obj,
        message: msg,
        confidence: v.kind === 'passthrough' ? 'high' : v.kind === 'partial' ? 'medium' : 'low',
        severity: v.kind === 'custom' ? 'medium' : 'high',
        evidenceKind: v.kind === 'custom' ? 'heuristic' : 'pattern',
        evidence: [`provide: ${name}`, `implementation: ${implName} (line ${ctx.location(fn).line})`, v.detail],
      });
    };
    for (const sf of ctx.sourceFiles) visit(sf);
    return findings;
  },
});
