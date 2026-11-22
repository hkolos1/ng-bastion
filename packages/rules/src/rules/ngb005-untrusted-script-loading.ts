import type * as ts from 'typescript';
import { defineRule, type RuleFinding } from '@ngbastion/plugin-api';
import { constantPrefix, hasFixedOrigin, is, memberName, methodCall, receiverOf, reportSink, strip } from '../shared/common.js';

export const ngb005 = defineRule({
  meta: {
    id: 'NGB005',
    name: 'Untrusted dynamic script loading',
    category: 'angular-xss',
    defaultSeverity: 'high',
    cwe: ['CWE-829'],
    docs: {
      description:
        'Tracks `<script>` elements created with `document.createElement("script")` or `Renderer2.createElement("script")` and reports when their `src` (or inline text) comes from an untrusted source, is fully dynamic with an unknown origin, or uses plain `http://`. Also covers dynamic `import()` with a non-constant specifier and `importScripts()`.',
      rationale:
        'A script loaded from an attacker-chosen URL runs with full access to your application. Plain-HTTP script URLs can be replaced by anyone on the network path.',
      patterns: [
        '`const s = document.createElement("script"); s.src = url` / `s.setAttribute("src", url)` / `s.text|textContent|innerHTML = code`',
        '`const s = renderer.createElement("script"); renderer.setAttribute(s, "src", url)` / `renderer.setProperty(s, "src", url)`',
        '`import(specifier)` and `importScripts(url)` with a non-literal argument',
        'Constant `https://` URLs and URLs with a fixed `https://host/` prefix are treated as explicitly trusted locations',
      ],
      limitations: [
        'Only script elements stored in a local variable or class field are tracked; elements passed through helper functions are not.',
        'Script tags injected via HTML strings are covered by NGB003, not this rule.',
      ],
      falsePositives: ['Loader helpers that receive URLs only from your own configuration may be reported with low confidence when that configuration is loaded at runtime.'],
      remediation:
        'Load third-party scripts only from constant HTTPS URLs (ideally with Subresource Integrity via `s.integrity` and `s.crossOrigin = "anonymous"`). Map dynamic choices to a constant allowlist instead of accepting URLs.',
      example: {
        unsafe: `const s = document.createElement('script');
s.src = this.route.snapshot.queryParams['widget'];
document.body.appendChild(s);`,
        safe: `const WIDGETS = { chat: 'https://cdn.example.com/chat.v3.js' } as const;
const s = document.createElement('script');
s.src = WIDGETS.chat;
document.body.appendChild(s);`,
      },
    },
  },
  analyze(ctx) {
    const t = ctx.ts;
    const findings: RuleFinding[] = [];
    const scriptSymbols = new Set<ts.Symbol>();

    const report = (sink: ts.Node, value: ts.Expression, what: string, inline: boolean) => {
      const prefix = inline ? undefined : constantPrefix(ctx, value);
      const constant = inline ? undefined : ctx.symbols.constantString(value);
      if (constant !== undefined && /^http:\/\//i.test(constant)) {
        findings.push({ node: sink, message: `Script is loaded over plain HTTP (${constant}); it can be replaced in transit.`, confidence: 'high', severity: 'medium', evidenceKind: 'pattern', evidence: ['constant script URL uses http://'] });
        return;
      }
      findings.push(...reportSink({
        ctx,
        sink,
        value,
        context: inline ? 'code' : 'resource-url',
        sinkDescription: what,
        message: (f) => `Untrusted data (${f.source.description}) controls ${what}.`,
        ...(hasFixedOrigin(prefix) ? {} : { unresolvedMessage: `${what} is set from a dynamic value whose origin could not be determined; restrict it to trusted script locations.` }),
        severity: (f) => (inline && f ? 'critical' : undefined),
      }));
    };

    // 1. find script elements
    for (const call of ctx.index.calls) {
      const callee = strip(ctx, call.expression);
      if (memberName(ctx, callee) !== 'createElement' || !call.arguments[0]) continue;
      if (ctx.symbols.constantString(call.arguments[0])?.toLowerCase() !== 'script') continue;
      const recv = receiverOf(ctx, callee)!;
      const ro = ctx.symbols.typeOrigin(recv);
      if (!is(ro, 'dom', 'Document') && !is(ro, '@angular/core', 'Renderer2')) continue;
      let p: ts.Node = call.parent;
      while (t.isParenthesizedExpression(p) || t.isAsExpression(p)) p = p.parent;
      const holder = t.isVariableDeclaration(p) || t.isPropertyDeclaration(p) ? p.name : t.isBinaryExpression(p) && p.right === call || t.isBinaryExpression(p) && strip(ctx, p.right) === call ? p.left : undefined;
      const sym = holder && ctx.checker.getSymbolAtLocation(t.isPropertyAccessExpression(holder) ? holder.name : holder);
      if (sym) scriptSymbols.add(sym);
    }
    const isScript = (e: ts.Expression | undefined) => {
      if (!e) return false;
      const x = strip(ctx, e);
      const sym = ctx.checker.getSymbolAtLocation(t.isPropertyAccessExpression(x) ? x.name : x);
      return !!sym && scriptSymbols.has(sym);
    };

    // 2. writes to script elements
    for (const a of ctx.index.assignments) {
      const prop = memberName(ctx, a.left);
      if (!prop || !isScript(receiverOf(ctx, a.left))) continue;
      if (prop === 'src') report(a, a.right, 'the script src', false);
      else if (['text', 'textContent', 'innerHTML', 'innerText'].includes(prop)) report(a, a.right, `inline script ${prop}`, true);
    }
    for (const call of ctx.index.calls) {
      const callee = strip(ctx, call.expression);
      const name = memberName(ctx, callee);
      if (name === 'setAttribute' && isScript(receiverOf(ctx, callee)) && call.arguments[1]
        && ctx.symbols.constantString(call.arguments[0]!)?.toLowerCase() === 'src') {
        report(call, call.arguments[1], 'the script src', false);
      }
      const r2 = methodCall(ctx, call, '@angular/core', ['Renderer2'], ['setAttribute', 'setProperty']);
      if (r2 && isScript(call.arguments[0]) && call.arguments[2]) {
        const key = ctx.symbols.constantString(call.arguments[1]!);
        if (key === 'src') report(call, call.arguments[2], 'the script src', false);
        else if (key && ['text', 'textContent', 'innerHTML'].includes(key)) report(call, call.arguments[2], `inline script ${key}`, true);
      }
      // 3. dynamic import() / importScripts()
      if (call.expression.kind === t.SyntaxKind.ImportKeyword && call.arguments[0] && !t.isStringLiteralLike(strip(ctx, call.arguments[0]))) {
        report(call, call.arguments[0], 'a dynamic import() specifier', false);
      }
      if (t.isIdentifier(callee) && callee.text === 'importScripts' && !ctx.symbols.callee(call)?.declaration) {
        for (const arg of call.arguments) report(call, arg, 'importScripts()', false);
      }
    }
    return findings;
  },
});
