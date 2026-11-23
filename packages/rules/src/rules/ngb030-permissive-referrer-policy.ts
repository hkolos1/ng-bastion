import type * as ts from 'typescript';
import { defineRule, type RuleFinding, type Severity, type SourceLocation } from '@ngbastion/plugin-api';
import { domElement, memberName, receiverOf, relative, strip, codeFiles } from '../shared/common.js';
import { hostingHeaders, htmlTags } from '../shared/files.js';

const WEAK: Record<string, { severity: Severity; why: string }> = {
  'unsafe-url': { severity: 'medium', why: 'sends the full URL (path and query string, including any tokens or IDs in it) to every destination, even over plain HTTP' },
  'no-referrer-when-downgrade': { severity: 'low', why: 'sends the full URL (path and query string) to every other HTTPS origin' },
};

/** The effective policy of a comma-separated list is the last recognized token. */
function effective(value: string): string {
  const tokens = value.toLowerCase().split(',').map((s) => s.trim()).filter(Boolean);
  return tokens[tokens.length - 1] ?? '';
}

export const ngb030 = defineRule({
  meta: {
    id: 'NGB030',
    name: 'Permissive referrer policy',
    category: 'security-config',
    defaultSeverity: 'medium',
    cwe: ['CWE-200', 'CWE-598'],
    docs: {
      description:
        "Reports explicit referrer policies that send full URLs to other origins: `unsafe-url` (medium) and `no-referrer-when-downgrade` (low). Looks at `<meta name=\"referrer\">` and `referrerpolicy` attributes in index.html, `referrerpolicy` attributes in Angular templates, `referrerPolicy` in `fetch()` options and on elements, `setAttribute('referrerpolicy', …)`, `Referrer-Policy` headers set in TypeScript (SSR) and in hosting configs.",
      rationale:
        "Browsers default to `strict-origin-when-cross-origin`, which only sends the origin to other sites. Weakening it leaks complete URLs — password-reset tokens, invite codes, search terms, internal IDs — to every third-party image, script, iframe and link target through the `Referer` header. NGB017 reports secrets placed in URLs; this rule reports the setting that broadcasts them.",
      patterns: [
        '`<meta name="referrer" content="unsafe-url">` and `<a|img|iframe|script|link referrerpolicy="…">` in index.html',
        'Static `referrerpolicy="…"` attributes in component templates',
        "`fetch(url, { referrerPolicy: 'unsafe-url' })`, `el.referrerPolicy = '…'`, `el.setAttribute('referrerpolicy', '…')`",
        "`res.setHeader('Referrer-Policy', '…')` / `{ 'Referrer-Policy': '…' }` with constant values, and headers in `firebase.json`, `vercel.json`, `staticwebapp.config.json`, `_headers`",
        'Comma-separated fallback lists are evaluated by their last token, as browsers do',
      ],
      limitations: [
        'Headers configured outside the repository (CDN, reverse proxy) are not visible; no finding is produced for them.',
        'Dynamic policy values are not evaluated.',
      ],
      falsePositives: [
        'An `unsafe-url` policy on a single element whose destination is your own origin leaks nothing; it is still reported because the setting is fragile.',
      ],
      remediation:
        "Remove the override (the browser default `strict-origin-when-cross-origin` is safe), or set `strict-origin-when-cross-origin`, `same-origin` or `no-referrer`. Do not put secrets in URLs in the first place (NGB017).",
      example: {
        unsafe: `<meta name="referrer" content="unsafe-url">`,
        safe: `<meta name="referrer" content="strict-origin-when-cross-origin">`,
      },
      references: [
        { title: 'MDN — Referrer-Policy', url: 'https://developer.mozilla.org/docs/Web/HTTP/Headers/Referrer-Policy' },
        { title: 'W3C — Referrer Policy', url: 'https://www.w3.org/TR/referrer-policy/' },
      ],
    },
  },
  analyze(ctx) {
    const t = ctx.ts;
    const findings: RuleFinding[] = [];
    const report = (at: { node: ts.Node } | { location: SourceLocation }, value: string | undefined, where: string) => {
      if (value === undefined) return;
      const policy = effective(value);
      const w = Object.hasOwn(WEAK, policy) ? WEAK[policy] : undefined;
      if (!w) return;
      findings.push({ ...at, message: `${where} sets referrer policy '${policy}', which ${w.why}.`, confidence: 'high', severity: w.severity, evidenceKind: 'pattern', evidence: [`referrer policy: ${value}`] });
    };

    const index = ctx.project.indexHtml;
    const html = index && ctx.readFile(index);
    if (index && html) {
      for (const tag of htmlTags(html, index, ['meta', 'a', 'area', 'img', 'iframe', 'script', 'link'])) {
        if (tag.name === 'meta' && tag.attrs.get('name')?.toLowerCase() === 'referrer') report({ location: tag.location }, tag.attrs.get('content'), `<meta name="referrer"> in ${relative(ctx, index)}`);
        else if (tag.attrs.has('referrerpolicy')) report({ location: tag.location }, tag.attrs.get('referrerpolicy'), `<${tag.name}> in ${relative(ctx, index)}`);
      }
    }
    for (const tpl of ctx.templates) {
      for (const el of tpl.elements) {
        const a = el.attributes.find((x) => !x.bound && x.name.toLowerCase() === 'referrerpolicy');
        if (a) report({ location: a.location }, a.value, `<${el.name}> in ${tpl.component}`);
      }
    }
    for (const sf of codeFiles(ctx)) {
      const visit = (n: ts.Node): void => {
        if (t.isPropertyAssignment(n) && (t.isIdentifier(n.name) || t.isStringLiteralLike(n.name))) {
          const k = n.name.text.toLowerCase();
          if (k === 'referrerpolicy' || k === 'referrer-policy') report({ node: n }, ctx.symbols.constantString(n.initializer), k === 'referrerpolicy' ? 'Request options' : 'Response header');
        }
        t.forEachChild(n, visit);
      };
      visit(sf);
    }
    for (const a of ctx.index.assignments) {
      const left = strip(ctx, a.left);
      if (memberName(ctx, left) === 'referrerPolicy' && domElement(ctx, receiverOf(ctx, left)!)) report({ node: a }, ctx.symbols.constantString(a.right), 'Element');
    }
    for (const call of ctx.index.calls) {
      const name = memberName(ctx, strip(ctx, call.expression));
      const [k, v] = call.arguments;
      if (!k || !v) continue;
      const key = ctx.symbols.constantString(k)?.toLowerCase();
      if (name === 'setAttribute' && key === 'referrerpolicy') report({ node: call }, ctx.symbols.constantString(v), 'setAttribute()');
      else if ((name === 'setHeader' || name === 'header' || name === 'set' || name === 'append') && key === 'referrer-policy') report({ node: call }, ctx.symbols.constantString(v), 'Response header');
    }
    for (const h of hostingHeaders(ctx, 'Referrer-Policy')) report({ location: h.location }, h.value, `Referrer-Policy header in ${h.origin}`);
    return findings;
  },
});
