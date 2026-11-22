import type * as ts from 'typescript';
import { defineRule, type RuleFinding } from '@ngbastion/plugin-api';
import { domElement, is, memberName, methodCall, receiverOf, reportSink, strip } from '../shared/common.js';

const HTML_PROPERTIES = new Set(['innerHTML', 'outerHTML', 'srcdoc']);

export const ngb003 = defineRule({
  meta: {
    id: 'NGB003',
    name: 'DOM injection sink',
    category: 'angular-xss',
    defaultSeverity: 'high',
    cwe: ['CWE-79'],
    docs: {
      description:
        'Reports untrusted data written to raw DOM HTML sinks that bypass Angular templating: `innerHTML`/`outerHTML`/`srcdoc` assignments on elements (including `ElementRef.nativeElement`), `insertAdjacentHTML()`, `document.write()`, `Range.createContextualFragment()`, `setHTMLUnsafe()`, and `Renderer2.setProperty(el, "innerHTML", v)`.',
      rationale:
        'Angular sanitizes `[innerHTML]` template bindings, but direct DOM APIs receive the raw string. Attacker-controlled markup reaching them executes in the application origin.',
      patterns: [
        '`el.innerHTML = v`, `el.outerHTML = v`, `iframe.srcdoc = v` (also `+=`) where `el` is a DOM element type or `ElementRef.nativeElement`',
        '`el.insertAdjacentHTML(position, v)`, `el.setHTMLUnsafe(v)`, `document.write(v)` / `writeln(v)`, `range.createContextualFragment(v)`',
        '`renderer.setProperty(el, "innerHTML" | "outerHTML" | "srcdoc", v)` and `renderer.setAttribute(el, "srcdoc", v)` with `Renderer2` from `@angular/core`',
        'Template `[innerHTML]` bindings are intentionally NOT reported: Angular sanitizes them',
      ],
      limitations: [
        'An untyped receiver is only treated as an element when it is `….nativeElement`; other `any`-typed objects are skipped.',
        'jQuery/third-party DOM helpers (`$(el).html(v)`) are not modeled.',
      ],
      falsePositives: [
        'Markup produced by a trusted rendering library from untrusted input (e.g. a Markdown renderer configured to escape HTML) is reported with reduced confidence because the library call is unmodeled.',
      ],
      remediation:
        'Prefer template binding (`[innerHTML]`, which Angular sanitizes) or `textContent` for text. If raw HTML is required, sanitize it with DOMPurify immediately before insertion.',
      example: {
        unsafe: `this.host.nativeElement.innerHTML = this.route.snapshot.queryParams['msg'];`,
        safe: `this.host.nativeElement.textContent = this.route.snapshot.queryParams['msg'];`,
      },
      references: [{ title: 'OWASP DOM XSS prevention', url: 'https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html' }],
    },
  },
  analyze(ctx) {
    const t = ctx.ts;
    const findings: RuleFinding[] = [];
    const report = (sink: ts.Node, value: ts.Expression, description: string, certain: boolean) => findings.push(...reportSink({
      ctx,
      sink,
      value,
      context: 'html',
      sinkDescription: description,
      sinkCertain: certain,
      message: (f) => `Untrusted data (${f.source.description}) is written to ${description} without sanitization.`,
      unresolvedMessage: `A dynamic value of unknown origin is written to ${description}; raw HTML sinks bypass Angular sanitization.`,
    }));

    for (const a of ctx.index.assignments) {
      const prop = memberName(ctx, a.left);
      if (!prop || !HTML_PROPERTIES.has(prop)) continue;
      const target = receiverOf(ctx, a.left)!;
      const el = domElement(ctx, target);
      if (!el) continue;
      report(a, a.right, `${prop}`, el.certain);
    }

    for (const call of ctx.index.calls) {
      const callee = strip(ctx, call.expression);
      const name = memberName(ctx, callee);
      const recv = receiverOf(ctx, callee);
      if (!name || !recv) continue;
      if ((name === 'insertAdjacentHTML' && call.arguments[1]) || (name === 'setHTMLUnsafe' && call.arguments[0])) {
        const el = domElement(ctx, recv);
        if (el) report(call, call.arguments[name === 'insertAdjacentHTML' ? 1 : 0]!, `${name}()`, el.certain);
        continue;
      }
      if ((name === 'write' || name === 'writeln') && call.arguments[0] && is(ctx.symbols.typeOrigin(recv), 'dom', 'Document')) {
        report(call, call.arguments[0], `document.${name}()`, true);
        continue;
      }
      if (name === 'createContextualFragment' && call.arguments[0] && is(ctx.symbols.typeOrigin(recv), 'dom', 'Range')) {
        report(call, call.arguments[0], 'Range.createContextualFragment()', true);
        continue;
      }
      const r2 = methodCall(ctx, call, '@angular/core', ['Renderer2'], ['setProperty', 'setAttribute']);
      if (r2 && call.arguments[2]) {
        const key = ctx.symbols.constantString(call.arguments[1]!);
        const ok = r2.info.name === 'setProperty' ? key && HTML_PROPERTIES.has(key) : key === 'srcdoc';
        if (ok) report(call, call.arguments[2], `Renderer2.${r2.info.name}(…, '${key}')`, true);
      }
    }
    void t;
    return findings;
  },
});
