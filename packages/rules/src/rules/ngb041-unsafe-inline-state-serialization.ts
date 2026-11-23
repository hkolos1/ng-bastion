import type * as ts from 'typescript';
import { defineRule, type AnalysisContext, type Confidence, type RuleFinding } from '@ngbastion/plugin-api';
import { codeFiles, memberName, receiverOf, strip } from '../shared/common.js';
import { urlParts } from '../shared/http.js';
import { sensitiveValue } from '../shared/sensitivity.js';

/** Escaping that neutralizes `</script>` and `<!--` inside inline scripts. */
const ESCAPED = /serialize|devalue|escape|sanitiz|toJsonForScript|\.replace(All)?\(\s*\/(<|\\u003c|\[<)/i;
const SERVER_FILE = /(^|[/\\])(server|main\.server|app\.config\.server)\.ts$|\.server\.ts$|[/\\]server[/\\]/;
const UNTRUSTED = new Set(['url', 'message', 'window-name', 'referrer', 'user-input', 'http-response', 'storage', 'cookie', 'request-header']);

/** The value (or the `const` it was read from) passed through a recognized escaping step. */
function escaped(ctx: AnalysisContext, e: ts.Expression): boolean {
  const t = ctx.ts;
  if (ESCAPED.test(e.getText())) return true;
  const x = strip(ctx, e);
  if (!t.isIdentifier(x)) return false;
  const d = ctx.symbols.declarationOf(x);
  return !!d && t.isVariableDeclaration(d) && !!d.initializer && ESCAPED.test(d.initializer.getText());
}

function confidenceFor(ctx: AnalysisContext, value: ts.Expression): { confidence: Confidence; evidence: string[] } {
  const result = ctx.taint.trace(value, { context: 'script' });
  const flow = result.flows.find((f) => UNTRUSTED.has(f.source.kind));
  const s = sensitiveValue(ctx, value);
  return {
    confidence: flow ? 'high' : 'medium',
    evidence: [
      ...(flow ? [`value traced to ${flow.source.description}`] : ['value origin not resolved to a modeled source']),
      ...(s ? [`serialized data includes ${s.category === 'payment' ? 'payment data' : 'credentials'}: ${s.evidence[0]}`] : []),
    ],
  };
}

/** Inside a server-only code path: SSR file or an `isPlatformServer(...)` guard. */
function serverSide(ctx: AnalysisContext, node: ts.Node): boolean {
  if (SERVER_FILE.test(node.getSourceFile().fileName)) return true;
  return ctx.flow.guards(node).some((g) => g.whenTrue && /isPlatformServer\(/.test(g.condition.getText()));
}

export const ngb041 = defineRule({
  meta: {
    id: 'NGB041',
    name: 'Unsafe inline state serialization',
    category: 'ssr',
    defaultSeverity: 'high',
    cwe: ['CWE-79', 'CWE-116'],
    docs: {
      description:
        "Reports application state written into an inline `<script>` without escaping, the hand-written alternative to Angular `TransferState`: HTML strings such as `` `<script>window.__STATE__ = ${JSON.stringify(state)}</script>` `` (server-rendered responses, `res.send()`, `html.replace('</head>', …)`), and SSR code that sets `textContent` / `text` / `innerHTML` of a `<script>` element it created. Confidence is high when the value is traced to request, HTTP, storage or URL data.",
      rationale:
        "`JSON.stringify` does not escape `<`, so a string value containing `</script><script>alert(1)</script>` (a user's display name, a product review, a query parameter) closes the inline script and injects markup into every page rendered with it: stored or reflected XSS during SSR. Angular's TransferState escapes `<`, `>` and `&` for exactly this reason. Personal data placed in such scripts is also delivered to — and cached by — every intermediary.",
      patterns: [
        'Template literals and `+` concatenations whose constant text opens `<script…>` before a dynamic value (any type, including `application/json` and `application/ld+json` blocks)',
        "`script.textContent = …`, `script.text = …`, `script.innerHTML = …` on elements from `document.createElement('script')` / `Renderer2.createElement('script')` in SSR files (`server.ts`, `*.server.ts`) or under `isPlatformServer(…)`",
        'Recognized escaping: `serialize-javascript`, `devalue`, functions named `escape…` / `sanitize…`, and `.replace(/</g, …)`',
      ],
      limitations: [
        'Strings assembled across several functions or in templates outside TypeScript (e.g. EJS views) are not followed.',
        'Browser-only code that sets a live script element\'s `textContent` is not reported (no HTML parsing happens there).',
      ],
      falsePositives: [
        'Values that can never contain `<` (numbers, booleans, enums) serialized this way are reported with medium confidence when their origin is not resolved.',
      ],
      remediation:
        "Use Angular `TransferState` (or `provideClientHydration()` HTTP transfer cache) instead of hand-written state scripts. If you must inline JSON, escape it: `JSON.stringify(state).replace(/</g, '\\\\u003c')` or use `serialize-javascript`/`devalue`, and never include tokens or personal data that the page does not need.",
      example: {
        unsafe: "res.send(html.replace('</head>', `<script>window.__USER__ = ${JSON.stringify(user)}</script></head>`));",
        safe: "const json = JSON.stringify(user).replace(/</g, '\\\\u003c');\nres.send(html.replace('</head>', `<script>window.__USER__ = ${json}</script></head>`));",
      },
      references: [
        { title: 'OWASP — XSS Prevention: JavaScript contexts', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html' },
        { title: 'Angular — TransferState', url: 'https://angular.dev/api/core/TransferState' },
      ],
    },
  },
  analyze(ctx) {
    const t = ctx.ts;
    const findings: RuleFinding[] = [];
    for (const sf of codeFiles(ctx)) {
      const visit = (n: ts.Node): void => {
        const top = (t.isTemplateExpression(n) || (t.isBinaryExpression(n) && n.operatorToken.kind === t.SyntaxKind.PlusToken))
          && !(t.isBinaryExpression(n.parent) && n.parent.operatorToken.kind === t.SyntaxKind.PlusToken);
        if (top) {
          let text = '';
          for (const part of urlParts(ctx, n as ts.Expression)) {
            if (part.text !== undefined) {
              text += part.text;
              continue;
            }
            const open = text.toLowerCase().lastIndexOf('<script');
            const inScript = open >= 0 && open > text.toLowerCase().lastIndexOf('</script') && text.indexOf('>', open) > 0;
            if (inScript && !escaped(ctx, part.expr) && ctx.symbols.constantString(part.expr) === undefined) {
              const c = confidenceFor(ctx, part.expr);
              findings.push({
                node: n,
                message: `Value '${part.expr.getText().slice(0, 50)}' is written into an inline <script> without escaping '<'; a string containing </script> breaks out and injects HTML (XSS).`,
                confidence: c.confidence,
                evidenceKind: 'pattern',
                evidence: c.evidence,
              });
              break;
            }
            text += '';
          }
        }
        t.forEachChild(n, visit);
      };
      visit(sf);
    }
    // SSR: script elements whose content is set as text, then serialized into the HTML.
    for (const a of ctx.index.assignments) {
      const left = strip(ctx, a.left);
      const prop = memberName(ctx, left);
      if (!prop || !['textContent', 'text', 'innerHTML', 'innerText'].includes(prop)) continue;
      const recv = receiverOf(ctx, left);
      const d = recv && ctx.symbols.declarationOf(recv);
      const init = d && (t.isVariableDeclaration(d) || t.isPropertyDeclaration(d)) && d.initializer ? strip(ctx, d.initializer) : undefined;
      if (!init || !t.isCallExpression(init) || memberName(ctx, init.expression) !== 'createElement') continue;
      const tag = init.arguments[0] && ctx.symbols.constantString(init.arguments[0]);
      if (tag?.toLowerCase() !== 'script' || !serverSide(ctx, a) || escaped(ctx, a.right) || ctx.symbols.constantString(a.right) !== undefined) continue;
      const c = confidenceFor(ctx, a.right);
      findings.push({
        node: a,
        message: `SSR code sets the ${prop} of a <script> element to unescaped data; the server serializes it into the HTML, where '</script>' in the value breaks out (XSS).`,
        confidence: c.confidence,
        evidenceKind: 'pattern',
        evidence: [...c.evidence, 'runs during server-side rendering'],
      });
    }
    return findings;
  },
});
