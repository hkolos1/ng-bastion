import type * as ts from 'typescript';
import { defineRule, type AnalysisContext, type RuleFinding } from '@ngbastion/plugin-api';
import { ANGULAR_SANITIZER_MODULES, is, memberName, receiverOf, strip } from '../shared/common.js';
import { objectProp } from '../shared/http.js';

/** SecurityContext enum members (@angular/core) and their numeric values. */
const CONTEXTS: Record<string, string> = { '0': 'NONE', '1': 'HTML', '2': 'STYLE', '3': 'SCRIPT', '4': 'URL', '5': 'RESOURCE_URL' };
const NAMES = new Set(Object.values(CONTEXTS));

/** Context a sink needs, and why. */
const BYPASS: Record<string, string> = {
  bypassSecurityTrustHtml: 'HTML',
  bypassSecurityTrustStyle: 'STYLE',
  bypassSecurityTrustScript: 'SCRIPT',
  bypassSecurityTrustUrl: 'URL',
  bypassSecurityTrustResourceUrl: 'RESOURCE_URL',
};
const HTML_PROPS = new Set(['innerHTML', 'outerHTML']);

/** `SecurityContext.URL` / `SecurityContext['URL']` / `4` → `URL`. */
function contextName(ctx: AnalysisContext, e: ts.Expression | undefined): string | undefined {
  if (!e) return undefined;
  const x = strip(ctx, e);
  const t = ctx.ts;
  if (t.isNumericLiteral(x)) return CONTEXTS[x.text];
  const m = memberName(ctx, x);
  const recv = receiverOf(ctx, x);
  if (m && NAMES.has(m) && recv && /(^|\.)SecurityContext$/.test(strip(ctx, recv).getText())) return m;
  return undefined;
}

/** `sanitizer.sanitize(ctx, v)` on Angular's DomSanitizer / Sanitizer. */
function sanitizeCall(ctx: AnalysisContext, e: ts.Expression | undefined, depth = 0): ts.CallExpression | undefined {
  if (!e || depth > 3) return undefined;
  const t = ctx.ts;
  const x = strip(ctx, e);
  if (t.isBinaryExpression(x) && [t.SyntaxKind.QuestionQuestionToken, t.SyntaxKind.BarBarToken].includes(x.operatorToken.kind)) return sanitizeCall(ctx, x.left, depth + 1);
  if (t.isIdentifier(x)) {
    const d = ctx.symbols.declarationOf(x);
    if (d && t.isVariableDeclaration(d) && d.initializer && t.isVariableDeclarationList(d.parent) && d.parent.flags & t.NodeFlags.Const) return sanitizeCall(ctx, d.initializer, depth + 1);
    return undefined;
  }
  if (!t.isCallExpression(x)) return undefined;
  const info = ctx.symbols.callee(x);
  if (!info || info.name !== 'sanitize' || info.declaration) return undefined;
  return is(info.receiver, ANGULAR_SANITIZER_MODULES, 'DomSanitizer', 'Sanitizer') ? x : undefined;
}

/** What a value sanitized for `have` still allows in a `need` sink. */
function consequence(have: string, need: string): string {
  if (need === 'RESOURCE_URL') return 'URL sanitization only blocks dangerous schemes; any https:// script or frame source from another origin is still accepted';
  if (need === 'HTML') return `${have} sanitization does not escape or strip markup; the value can still inject HTML and script`;
  if (need === 'SCRIPT') return 'no sanitizer makes data safe to run as script';
  return `${have} sanitization does not apply the ${need} rules`;
}

export const ngb051 = defineRule({
  meta: {
    id: 'NGB051',
    name: 'Mismatched Angular sanitization context',
    category: 'angular-xss',
    defaultSeverity: 'high',
    cwe: ['CWE-116', 'CWE-79'],
    docs: {
      description:
        "Reports `DomSanitizer.sanitize()` calls whose security context does not match where the result is used (a value sanitized as a `URL` passed to `bypassSecurityTrustHtml()` or `bypassSecurityTrustResourceUrl()`, or assigned to `innerHTML`), `sanitize(SecurityContext.NONE, …)`, which returns its input unchanged, and ngx-markdown configured with `sanitize: SecurityContext.NONE` or `[disableSanitizer]=\"true\"`.",
      rationale:
        "Angular's sanitizer is context-specific: `SecurityContext.URL` only neutralizes dangerous URL schemes and leaves `<img onerror>` intact; `SecurityContext.HTML` leaves `https://evil.example/x.js` intact. Code that sanitizes for one context and then trusts the result in another looks reviewed but is not protected, and `SecurityContext.NONE` is a no-op that reads like a sanitizer call.",
      patterns: [
        '`bypassSecurityTrustHtml|Style|Script|Url|ResourceUrl(sanitizer.sanitize(SecurityContext.X, v))` where `X` is not the bypass context (also through a `const` and `?? \'\'`)',
        '`el.innerHTML = sanitizer.sanitize(SecurityContext.URL, v)` (any context other than HTML)',
        '`sanitizer.sanitize(SecurityContext.NONE, v)` / `sanitize(0, v)`',
        "ngx-markdown: `provideMarkdown({ sanitize: SecurityContext.NONE })`, `MarkdownModule.forRoot({ sanitize: SecurityContext.NONE })`, `<markdown [disableSanitizer]=\"true\">`",
      ],
      limitations: [
        'The sanitized value is followed through `const` variables only; storing it in a property and trusting it elsewhere is not linked.',
        'Whether the value is attacker-controlled is not required: NGB001 / NGB002 report the trust bypass when the origin is traced.',
      ],
      falsePositives: [
        '`SecurityContext.NONE` on values that are constant or already trusted (`SafeValue`s) is reported; use the value directly instead.',
      ],
      remediation:
        'Sanitize with the context of the sink (`SecurityContext.HTML` before HTML, `URL` before URLs) and do not wrap the result in a `bypassSecurityTrust*()` call at all: bind it and let Angular sanitize. For resource URLs, check the value against an allowlist of origins instead of sanitizing it. Keep markdown rendering sanitized.',
      example: {
        unsafe: `const html = this.sanitizer.sanitize(SecurityContext.URL, comment) ?? '';
this.content = this.sanitizer.bypassSecurityTrustHtml(html);`,
        safe: `this.content = this.sanitizer.sanitize(SecurityContext.HTML, comment) ?? ''; // bound to [innerHTML]`,
      },
      references: [
        { title: 'Angular — Sanitization and security contexts', url: 'https://angular.dev/best-practices/security#sanitization-and-security-contexts' },
        { title: 'Angular API — SecurityContext', url: 'https://angular.dev/api/core/SecurityContext' },
        { title: 'ngx-markdown — Sanitization', url: 'https://github.com/jfcere/ngx-markdown#sanitization' },
      ],
    },
  },
  analyze(ctx) {
    const t = ctx.ts;
    const findings: RuleFinding[] = [];
    const reported = new Set<ts.Node>();
    const mismatch = (sink: ts.Node, value: ts.Expression, need: string, sinkName: string) => {
      const call = sanitizeCall(ctx, value);
      const have = call && contextName(ctx, call.arguments[0]);
      if (!call || !have || have === need || have === 'NONE' || reported.has(call)) return;
      reported.add(call);
      findings.push({
        node: sink,
        message: `Value sanitized for SecurityContext.${have} is used as ${need} (${sinkName}): ${consequence(have, need)}.`,
        confidence: 'high',
        severity: need === 'STYLE' || need === 'URL' ? 'medium' : 'high',
        evidenceKind: 'pattern',
        evidence: [`sanitize(SecurityContext.${have}) at line ${ctx.location(call).line}`, `sink requires SecurityContext.${need}`],
      });
    };

    for (const call of ctx.index.calls) {
      const info = ctx.symbols.callee(call);
      if (!info || info.declaration) continue;
      const need = Object.hasOwn(BYPASS, info.name) ? BYPASS[info.name] : undefined;
      if (need && call.arguments[0] && (!info.receiver || is(info.receiver, ANGULAR_SANITIZER_MODULES, 'DomSanitizer'))) mismatch(call, call.arguments[0], need, `${info.name}()`);

      if (info.name === 'sanitize' && is(info.receiver, ANGULAR_SANITIZER_MODULES, 'DomSanitizer', 'Sanitizer') && contextName(ctx, call.arguments[0]) === 'NONE') {
        findings.push({
          node: call,
          message: 'sanitize(SecurityContext.NONE, …) returns the value unchanged; it does not sanitize anything.',
          confidence: 'high',
          severity: 'medium',
          evidenceKind: 'pattern',
          evidence: ['SecurityContext.NONE disables sanitization'],
        });
      }

      // ngx-markdown global configuration.
      if ((info.name === 'provideMarkdown' || info.name === 'forRoot') && (info.origin?.module === 'ngx-markdown' || info.receiver?.module === 'ngx-markdown')) {
        const sanitize = objectProp(ctx, call.arguments[0], 'sanitize');
        if (sanitize && contextName(ctx, sanitize) === 'NONE') {
          findings.push({
            node: sanitize,
            message: 'ngx-markdown is configured with sanitize: SecurityContext.NONE; rendered markdown (including raw HTML) reaches the DOM without sanitization.',
            confidence: 'high',
            severity: 'high',
            evidenceKind: 'pattern',
            evidence: [`${info.name}() from ngx-markdown`, 'sanitize: SecurityContext.NONE'],
          });
        }
      }
    }

    for (const a of ctx.index.assignments) {
      if (a.operatorToken.kind !== t.SyntaxKind.EqualsToken) continue;
      const prop = memberName(ctx, a.left);
      if (prop && HTML_PROPS.has(prop)) mismatch(a, a.right, 'HTML', `${prop} assignment`);
    }

    for (const tpl of ctx.templates) {
      for (const el of tpl.elements) {
        if (el.name !== 'markdown') continue;
        const attr = el.attributes.find((x) => x.name === 'disableSanitizer' && (x.bound ? x.value.trim() === 'true' : x.value === '' || x.value === 'true'));
        if (!attr) continue;
        findings.push({
          location: attr.location,
          message: '<markdown disableSanitizer> renders markdown (including raw HTML) without sanitization.',
          confidence: 'high',
          severity: 'high',
          evidenceKind: 'pattern',
          evidence: [`template of ${tpl.component}`],
        });
      }
    }
    return findings;
  },
});
