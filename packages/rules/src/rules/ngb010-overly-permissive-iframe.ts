import type * as ts from 'typescript';
import { defineRule, type AnalysisContext, type RuleFinding, type SourceLocation } from '@ngbastion/plugin-api';
import { is, memberName, receiverOf, relative, strip } from '../shared/common.js';

const POWERFUL = ['camera', 'microphone', 'geolocation', 'payment', 'usb', 'serial', 'hid', 'clipboard-read', 'display-capture', 'bluetooth', 'midi'];

/** Normalized view of one iframe, whatever syntax declared it. */
interface IframeInfo {
  where: string;
  location: SourceLocation;
  node?: ts.Node;
  /** undefined = attribute absent; null = present but dynamic (bound/non-constant). */
  sandbox: string | null | undefined;
  allow: string | null | undefined;
  src: { dynamic: boolean; value?: string } | undefined;
}

function check(ctx: AnalysisContext, f: IframeInfo): RuleFinding[] {
  const at = f.node ? { node: f.node } : { location: f.location };
  const out: RuleFinding[] = [];
  if (f.sandbox === null) {
    ctx.diagnostic({ code: 'unsupported-construct', level: 'info', message: `NGB010: ${f.where} has a dynamic sandbox attribute; its tokens cannot be assessed statically`, file: f.location.file });
  }
  if (typeof f.sandbox === 'string') {
    const tokens = new Set(f.sandbox.toLowerCase().split(/\s+/).filter(Boolean));
    if (tokens.has('allow-scripts') && tokens.has('allow-same-origin')) {
      out.push({
        ...at,
        message: `${f.where}: sandbox combines allow-scripts and allow-same-origin; same-origin content can remove its own sandbox, so the sandbox provides no isolation.`,
        confidence: 'high',
        evidenceKind: 'pattern',
        evidence: [`sandbox="${f.sandbox}"`],
      });
    }
    if (tokens.has('allow-scripts') && (tokens.has('allow-top-navigation') || tokens.has('allow-popups-to-escape-sandbox')) && f.src?.dynamic) {
      out.push({
        ...at,
        message: `${f.where}: sandbox lets scripts in dynamically chosen content navigate the top window or open unsandboxed popups.`,
        confidence: 'medium',
        evidenceKind: 'pattern',
        evidence: [`sandbox="${f.sandbox}"`, 'src is dynamic'],
      });
    }
  }
  if (typeof f.allow === 'string') {
    // `feature` alone defaults to the iframe's own (here: dynamic) src origin; `*` / 'src' are equally open.
    const entries = f.allow.split(';').map((s) => s.trim().split(/\s+/)).filter((x) => x[0]);
    const open = (list: string[]) => !list.length || list.some((o) => o === '*' || o === "'src'");
    const delegated = entries.filter(([name, ...list]) => POWERFUL.includes(name!.toLowerCase()) && open(list)).map(([name]) => name!);
    const wildcard = entries.some(([name]) => name === '*');
    if ((delegated.length || wildcard) && f.src?.dynamic) {
      out.push({
        ...at,
        message: `${f.where}: powerful permissions (${[...delegated, ...(wildcard ? ['*'] : [])].join(', ')}) are delegated to an iframe whose source is dynamic.`,
        confidence: 'medium',
        evidenceKind: 'pattern',
        evidence: [`allow="${f.allow}"`, 'src is dynamic'],
      });
    }
  }
  if (f.sandbox === undefined && f.src?.dynamic) {
    out.push({
      ...at,
      message: `${f.where}: iframe loads a dynamic source without a sandbox attribute; if the content can be untrusted, restrict it with sandbox.`,
      confidence: 'low',
      severity: 'low',
      evidenceKind: 'heuristic',
      evidence: ['no sandbox attribute', 'src is bound to a dynamic value'],
    });
  }
  return out;
}

/** `<iframe …>` tags in a static HTML file (index.html). */
function htmlIframes(ctx: AnalysisContext, file: string): IframeInfo[] {
  const text = ctx.readFile(file);
  if (!text) return [];
  const out: IframeInfo[] = [];
  for (const m of text.matchAll(/<iframe\b([^>]*)>/gi)) {
    const attrs = new Map<string, string>();
    for (const a of m[1]!.matchAll(/([\w:-]+)(?:\s*=\s*("([^"]*)"|'([^']*)'|([^\s>]+)))?/g)) attrs.set(a[1]!.toLowerCase(), a[3] ?? a[4] ?? a[5] ?? '');
    const line = text.slice(0, m.index).split('\n').length;
    out.push({
      where: `<iframe> in ${relative(ctx, file)}`,
      location: { file, line, column: 1, endLine: line, endColumn: 1 },
      sandbox: attrs.get('sandbox'),
      allow: attrs.get('allow'),
      src: attrs.has('src') ? { dynamic: false, value: attrs.get('src')! } : undefined,
    });
  }
  return out;
}

export const ngb010 = defineRule({
  meta: {
    id: 'NGB010',
    name: 'Overly permissive iframe',
    category: 'cross-window',
    defaultSeverity: 'medium',
    cwe: ['CWE-1021', 'CWE-250'],
    docs: {
      description:
        'Inspects iframes declared in Angular templates, in `index.html`, and created with `document.createElement("iframe")`. Reports sandboxes that combine `allow-scripts` with `allow-same-origin`, sandboxes that let dynamic content escape (`allow-top-navigation`, `allow-popups-to-escape-sandbox`), powerful permission delegation (`allow="camera; microphone; payment …"` or `*`) to dynamically chosen sources, and — with low confidence — unsandboxed iframes whose `src` is bound to a dynamic value.',
      rationale:
        'An iframe inherits nothing by default, but `allow` delegates powerful browser features, and an ineffective sandbox gives untrusted framed content script access. With both `allow-scripts` and `allow-same-origin`, same-origin content can simply remove the sandbox attribute from its own frame.',
      patterns: [
        'Template elements `<iframe sandbox="…" allow="…" [src]="…">` (inline and external templates)',
        '`index.html` iframes (static attributes)',
        '`const f = document.createElement("iframe")` with `f.sandbox = …` / `f.setAttribute("sandbox" | "allow", …)` / `f.allow = …` / `f.src = …`',
        'A static, constant `src` without sandbox is NOT reported; dynamic `[src]` without sandbox is reported with low confidence',
      ],
      limitations: [
        'Dynamic `[attr.sandbox]` / `[sandbox]` bindings cannot be assessed and produce an informational diagnostic instead of a finding.',
        'Whether the framed content is trusted is not known statically; only the shape of the configuration is assessed.',
        'Iframes created via `Renderer2.createElement` or third-party components are not covered.',
      ],
      falsePositives: [
        'Trusted first-party content embedded from a dynamic but allowlisted URL is reported with low confidence when unsandboxed.',
      ],
      remediation:
        'Use the narrowest sandbox that works (start from `sandbox=""` and add tokens) and never combine `allow-scripts` with `allow-same-origin` for content you do not fully control. Delegate powerful features only to fixed, trusted origins (`allow="payment https://pay.example.com"`).',
      example: {
        unsafe: `<iframe [src]="widgetUrl" sandbox="allow-scripts allow-same-origin" allow="camera; microphone"></iframe>`,
        safe: `<iframe [src]="widgetUrl" sandbox="allow-scripts" allow="camera https://video.example.com"></iframe>`,
      },
      references: [
        { title: 'MDN — <iframe> sandbox', url: 'https://developer.mozilla.org/docs/Web/HTML/Element/iframe#sandbox' },
        { title: 'MDN — Permissions Policy', url: 'https://developer.mozilla.org/docs/Web/HTTP/Permissions_Policy' },
      ],
    },
  },
  analyze(ctx) {
    const t = ctx.ts;
    const findings: RuleFinding[] = [];

    for (const tpl of ctx.templates) {
      for (const el of tpl.elements) {
        if (el.name.toLowerCase() !== 'iframe') continue;
        const attr = (name: string) => el.attributes.find((a) => a.name.toLowerCase() === name);
        const value = (name: string) => {
          const a = attr(name);
          return a === undefined ? undefined : a.bound ? null : a.value;
        };
        const src = attr('src');
        findings.push(...check(ctx, {
          where: `<iframe> in ${tpl.component}`,
          location: el.location,
          sandbox: value('sandbox'),
          allow: value('allow'),
          src: src ? { dynamic: src.bound } : undefined,
        }));
      }
    }

    if (ctx.project.indexHtml) for (const f of htmlIframes(ctx, ctx.project.indexHtml)) findings.push(...check(ctx, f));

    // DOM-created iframes
    const frames = new Map<ts.Symbol, IframeInfo>();
    const symOf = (e: ts.Expression | undefined) => {
      if (!e) return undefined;
      const x = strip(ctx, e);
      return ctx.checker.getSymbolAtLocation(t.isPropertyAccessExpression(x) ? x.name : x);
    };
    for (const call of ctx.index.calls) {
      const callee = strip(ctx, call.expression);
      if (memberName(ctx, callee) !== 'createElement' || ctx.symbols.constantString(call.arguments[0] ?? callee)?.toLowerCase() !== 'iframe') continue;
      if (!is(ctx.symbols.typeOrigin(receiverOf(ctx, callee)!), 'dom', 'Document')) continue;
      let p: ts.Node = call.parent;
      while (t.isParenthesizedExpression(p) || t.isAsExpression(p)) p = p.parent;
      const holder = t.isVariableDeclaration(p) || t.isPropertyDeclaration(p) ? p.name : t.isBinaryExpression(p) ? p.left : undefined;
      const sym = holder && symOf(holder as ts.Expression);
      if (sym) frames.set(sym, { where: 'iframe created with document.createElement', location: ctx.location(call), node: call, sandbox: undefined, allow: undefined, src: undefined });
    }
    if (frames.size) {
      const set = (sym: ts.Symbol | undefined, prop: string, valueExpr: ts.Expression) => {
        const f = sym && frames.get(sym);
        if (!f) return;
        const v = ctx.symbols.constantString(valueExpr);
        if (prop === 'sandbox') f.sandbox = v ?? null;
        else if (prop === 'allow') f.allow = v ?? null;
        else if (prop === 'src') f.src = { dynamic: v === undefined, ...(v !== undefined ? { value: v } : {}) };
      };
      for (const a of ctx.index.assignments) {
        const prop = memberName(ctx, a.left);
        if (prop) set(symOf(receiverOf(ctx, a.left)), prop, a.right);
      }
      for (const call of ctx.index.calls) {
        const callee = strip(ctx, call.expression);
        const name = memberName(ctx, callee);
        const recv = receiverOf(ctx, callee);
        if (name === 'setAttribute' && call.arguments[1]) {
          const key = ctx.symbols.constantString(call.arguments[0]!);
          if (key) set(symOf(recv), key.toLowerCase(), call.arguments[1]);
        }
        // frame.sandbox.add('allow-scripts', …)
        if (name === 'add' && recv && memberName(ctx, recv) === 'sandbox') {
          const f = frames.get(symOf(receiverOf(ctx, recv)) as ts.Symbol);
          if (f) {
            const tokens = call.arguments.map((x) => ctx.symbols.constantString(x));
            f.sandbox = tokens.some((x) => x === undefined) ? null : [f.sandbox ?? '', ...tokens].join(' ').trim();
          }
        }
      }
      for (const f of frames.values()) findings.push(...check(ctx, f));
    }
    return findings;
  },
});
