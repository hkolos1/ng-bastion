import type * as ts from 'typescript';
import { defineRule, type AnalysisContext, type RuleFinding } from '@ngbastion/plugin-api';
import { domElement, is, memberName, receiverOf, strip } from '../shared/common.js';

const GLOBAL_NAMES = new Set(['window', 'self', 'globalThis', 'document', 'top', 'parent', 'frames']);
const URL_PROPS = new Set(['src', 'href', 'action', 'formAction', 'innerHTML', 'outerHTML', 'srcdoc']);
const URL_ATTRS = /^(src|href|action|formaction|srcdoc|data|xlink:href)$/i;

interface GlobalRead {
  node: ts.Expression;
  name: string;
  receiver: 'window' | 'document';
  /** `window.cfg || {}` / `window.cfg ?? default`: the classic optional-global gadget. */
  fallback: boolean;
}

/** Receiver is the global window / document object. */
function globalReceiver(ctx: AnalysisContext, e: ts.Expression): 'window' | 'document' | undefined {
  const x = strip(ctx, e);
  const o = ctx.symbols.typeOrigin(x);
  if (is(o, 'dom', 'Document')) return 'document';
  if (is(o, 'dom', 'Window')) return 'window';
  if (ctx.ts.isIdentifier(x) && GLOBAL_NAMES.has(x.text)) {
    const d = ctx.symbols.declarationOf(x);
    if (!d || d.getSourceFile().isDeclarationFile) return x.text === 'document' ? 'document' : 'window';
  }
  return undefined;
}

/** Property is declared by the TypeScript DOM / ES libraries (not a project global or an `any` access). */
function standardProperty(ctx: AnalysisContext, receiver: ts.Expression, name: string): boolean {
  const type = ctx.checker.getTypeAtLocation(strip(ctx, receiver));
  const sym = type.getProperty(name) ?? ctx.checker.getApparentType(type).getProperty(name);
  const decls = sym?.declarations ?? [];
  return decls.length > 0 && decls.every((d) => {
    const sf = d.getSourceFile();
    return sf.hasNoDefaultLib || /[/\\]typescript[/\\]lib[/\\]lib\.[\w.]+\.d\.ts$/.test(sf.fileName);
  });
}

/** `window.X` / `(window as any).X` / `window['X']` / `document.X` reads of non-standard properties. */
function globalRead(ctx: AnalysisContext, e: ts.Expression): GlobalRead | undefined {
  const t = ctx.ts;
  const x = strip(ctx, e);
  if (!t.isPropertyAccessExpression(x) && !t.isElementAccessExpression(x)) return undefined;
  const name = memberName(ctx, x);
  const recv = receiverOf(ctx, x)!;
  const kind = name ? globalReceiver(ctx, recv) : undefined;
  if (!name || !kind || standardProperty(ctx, recv, name)) return undefined;
  let p: ts.Node = x;
  while (p.parent && (t.isParenthesizedExpression(p.parent) || t.isAsExpression(p.parent) || t.isNonNullExpression(p.parent))) p = p.parent;
  const fallback = t.isBinaryExpression(p.parent) && p.parent.left === p && [t.SyntaxKind.BarBarToken, t.SyntaxKind.QuestionQuestionToken].includes(p.parent.operatorToken.kind);
  return { node: x, name, receiver: kind, fallback };
}

/** Custom global reads that make up `value` (directly, as `window.cfg.url`, or through local variables). */
function globalReadsIn(ctx: AnalysisContext, value: ts.Expression, depth = 0): GlobalRead[] {
  const t = ctx.ts;
  const out: GlobalRead[] = [];
  const visit = (n: ts.Node): void => {
    if (t.isExpression(n)) {
      const g = globalRead(ctx, n);
      if (g) {
        out.push(g);
        return;
      }
    }
    if (t.isIdentifier(n) && depth < 3) {
      const d = ctx.symbols.declarationOf(n);
      if (d && t.isVariableDeclaration(d) && d.initializer && d.getSourceFile() === n.getSourceFile()) out.push(...globalReadsIn(ctx, d.initializer, depth + 1));
      return;
    }
    // Calls are not followed: their result is not the global itself.
    if (t.isCallExpression(n)) return;
    t.forEachChild(n, visit);
  };
  visit(value);
  return out;
}

/** Names the application itself assigns (`window.cfg = { … }`) — not clobberable once set, unless the assignment reads the global itself. */
function assignedGlobals(ctx: AnalysisContext): Set<string> {
  const out = new Set<string>();
  for (const a of ctx.index.assignments) {
    const g = globalRead(ctx, a.left);
    if (g && !globalReadsIn(ctx, a.right).some((r) => r.name === g.name)) out.add(g.name);
  }
  return out;
}

interface Sink { node: ts.Node; value: ts.Expression; what: string }

function sinks(ctx: AnalysisContext): Sink[] {
  const t = ctx.ts;
  const out: Sink[] = [];
  for (const a of ctx.index.assignments) {
    const left = strip(ctx, a.left);
    const name = memberName(ctx, left);
    const recv = receiverOf(ctx, left);
    if (name && recv && URL_PROPS.has(name) && (domElement(ctx, recv) || is(ctx.symbols.typeOrigin(recv), 'dom', 'Location'))) out.push({ node: a, value: a.right, what: `.${name} assignment` });
  }
  for (const call of ctx.index.calls) {
    const callee = strip(ctx, call.expression);
    const a = call.arguments;
    if (callee.kind === t.SyntaxKind.ImportKeyword && a[0]) out.push({ node: call, value: a[0], what: 'import()' });
    const name = t.isIdentifier(callee) ? callee.text : memberName(ctx, callee);
    if (name === 'setAttribute' && a[1] && URL_ATTRS.test(ctx.symbols.constantString(a[0]!) ?? '')) out.push({ node: call, value: a[1], what: `setAttribute('${ctx.symbols.constantString(a[0]!)}')` });
    else if (name === 'importScripts' && a[0]) out.push({ node: call, value: a[0], what: 'importScripts()' });
    else if ((name === 'assign' || name === 'replace') && a[0] && is(ctx.symbols.typeOrigin(receiverOf(ctx, callee) ?? callee), 'dom', 'Location')) out.push({ node: call, value: a[0], what: `location.${name}()` });
    else if ((name === 'write' || name === 'writeln') && a[0] && is(ctx.symbols.typeOrigin(receiverOf(ctx, callee) ?? callee), 'dom', 'Document')) out.push({ node: call, value: a[0], what: `document.${name}()` });
  }
  for (const n of ctx.index.newExpressions) {
    if (t.isIdentifier(n.expression) && /^(Worker|SharedWorker)$/.test(n.expression.text) && n.arguments?.[0]) out.push({ node: n, value: n.arguments[0], what: `new ${n.expression.text}()` });
  }
  return out;
}

export const ngb063 = defineRule({
  meta: {
    id: 'NGB063',
    name: 'DOM-clobberable global in a sensitive sink',
    category: 'angular-xss',
    defaultSeverity: 'medium',
    cwe: ['CWE-79', 'CWE-471'],
    docs: {
      description:
        "Reports script / URL / HTML sinks (`script.src`, `href`, `setAttribute('src' | 'href' | 'action')`, `import()`, `importScripts()`, `new Worker()`, `location.assign()`, `innerHTML`, `document.write()`) whose value comes from a non-standard property of `window` / `document` — `window.CONFIG.cdnUrl`, `(window as any).appSettings || {}`, `document.trustedHost` — that the application never assigns itself. Such globals can be created by injected HTML: an element with `id=\"CONFIG\"` becomes `window.CONFIG`, and `<form name=\"x\">` becomes `document.x` (DOM clobbering).",
      rationale:
        "HTML sanitizers (Angular's, DOMPurify with default settings) keep `id` and `name` attributes, so markup that cannot run script can still define globals. Code that treats an optional global as trusted configuration — the classic `const cfg = window.CONFIG || {}; script.src = cfg.cdn + '/x.js'` — then loads attacker-chosen script, navigates to `javascript:` URLs, or writes HTML: a script-less HTML injection becomes full XSS.",
      patterns: [
        'Global reads: `window.X`, `self.X`, `globalThis.X`, `window["X"]`, `(window as any).X`, `document.X` where `X` is not declared by the TypeScript DOM / ES libraries',
        'Sinks: `.src` / `.href` / `.action` / `.formAction` / `.innerHTML` / `.outerHTML` / `.srcdoc` assignments, `setAttribute("src" | "href" | "action" | "formaction" | "srcdoc" | "data")` on DOM elements, `import()`, `importScripts()`, `new Worker()`, `location.assign/replace()`, `document.write()`',
        'Followed: member chains (`window.cfg.cdn.url`), `+` / template concatenation and local `const` / `let` variables in the same file',
        'Medium confidence when the global has a fallback (`window.X || {}` / `??`), low otherwise',
        'Not reported: globals the application assigns (`window.CONFIG = { … }`) without reading the old value',
      ],
      limitations: [
        'Globals passed through functions, services or Angular DI before reaching the sink are not followed.',
        'Whether attacker HTML can reach the page (and with which attributes) is not assessed; this is a gadget, not a complete exploit chain.',
        'Globals assigned by a separate inline `<script>` in index.html are not seen and may still be reported.',
      ],
      falsePositives: [
        'Configuration injected by the server into a `<script>` before the application loads is not clobberable in practice; if it is assigned outside TypeScript sources, document an exception.',
      ],
      remediation:
        "Do not read security-relevant configuration from optional globals. Inject it through Angular DI (`InjectionToken` provided from a build-time environment or a fetched JSON), or verify the type explicitly (`typeof cfg.cdn === 'string' && !(cfg instanceof Element)`) and validate URLs against an allowlist. Enable DOMPurify's `SANITIZE_NAMED_PROPS` when rendering untrusted HTML.",
      example: {
        unsafe: `const cfg = (window as any).APP_CONFIG || {};
script.src = cfg.cdn + '/widget.js';`,
        safe: `const cfg = inject(APP_CONFIG); // provided from environment.ts
script.src = cfg.cdn + '/widget.js';`,
      },
      references: [
        { title: 'PortSwigger — DOM clobbering', url: 'https://portswigger.net/web-security/dom-based/dom-clobbering' },
        { title: 'OWASP — DOM Clobbering Prevention Cheat Sheet', url: 'https://cheatsheetseries.owasp.org/cheatsheets/DOM_Clobbering_Prevention_Cheat_Sheet.html' },
      ],
    },
  },
  analyze(ctx) {
    const findings: RuleFinding[] = [];
    let assigned: Set<string> | undefined;
    for (const s of sinks(ctx)) {
      const reads = globalReadsIn(ctx, s.value);
      if (!reads.length) continue;
      assigned ??= assignedGlobals(ctx);
      const read = reads.find((r) => !assigned!.has(r.name));
      if (!read) continue;
      const via = read.receiver === 'document' ? `a <form>/<img>/<embed> with name="${read.name}"` : `an element with id="${read.name}"`;
      findings.push({
        node: s.node,
        message: `${s.what} uses ${read.receiver}.${read.name}, a global the application never defines; injected HTML (${via}) can clobber it and control this value.`,
        confidence: read.fallback ? 'medium' : 'low',
        evidenceKind: 'heuristic',
        evidence: [`global: ${read.receiver}.${read.name} (not declared by the DOM library, never assigned in project code)`, `sink: ${s.what}`, ...(read.fallback ? ['optional-global pattern (|| / ?? fallback)'] : [])],
      });
    }
    return findings;
  },
});
