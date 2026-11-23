import type * as ts from 'typescript';
import { defineRule, type Confidence, type RuleFinding, type Severity } from '@ngbastion/plugin-api';
import { is, memberName, receiverOf, relative, strip } from '../shared/common.js';
import { htmlTags } from '../shared/files.js';

/** Providers that serve evolving content at a fixed URL, where SRI cannot be used. */
const NO_SRI_HOSTS = /(^|\.)(googletagmanager\.com|google-analytics\.com|js\.stripe\.com|maps\.googleapis\.com|fonts\.googleapis\.com|www\.google\.com|www\.gstatic\.com|connect\.facebook\.net|static\.cloudflareinsights\.com|challenges\.cloudflare\.com|js\.hcaptcha\.com|pay\.google\.com|applepay\.cdn-apple\.com|js\.braintreegateway\.com|www\.paypal\.com|cdn\.segment\.com|widget\.intercom\.io)$/i;

function externalHost(url: string | undefined): string | undefined {
  const m = url && /^\s*(?:https?:)?\/\/([^/?#:\s]+)/i.exec(url);
  return m ? m[1]!.toLowerCase() : undefined;
}

export const ngb045 = defineRule({
  meta: {
    id: 'NGB045',
    name: 'Missing subresource integrity',
    category: 'supply-chain',
    defaultSeverity: 'medium',
    cwe: ['CWE-353', 'CWE-829'],
    docs: {
      description:
        "Reports third-party scripts and stylesheets loaded from another origin without an `integrity` attribute: `<script src=\"https://cdn…\">` and `<link rel=\"stylesheet\" href=\"https://…\">` in index.html, and `<script>` elements created in code (`document.createElement('script')`, `Renderer2.createElement('script')`) whose constant external `src` is set without `integrity`. Providers that serve evolving scripts at a fixed URL (tag managers, payment SDKs, maps, captcha) are reported with low confidence because SRI cannot be applied to them.",
      rationale:
        "A script from a CDN runs with full access to your page. If the CDN, the package on it, or the connection is compromised, every visitor runs the attacker's code (polyfill.io in 2024 is the textbook case). `integrity=\"sha384-…\"` makes the browser refuse a file that differs from the one you reviewed.",
      patterns: [
        'index.html: `<script src>` with an absolute / protocol-relative URL and no `integrity` (medium severity); `<link rel="stylesheet" href>` likewise (low severity)',
        "Code: `const s = document.createElement('script'); s.src = 'https://cdn…'` without `s.integrity = …` / `setAttribute('integrity', …)` in the same scope (low confidence)",
        'Known evolving providers (Google Tag Manager / Analytics, Stripe.js, Google Maps / Fonts, reCAPTCHA, PayPal, Braintree, Segment, Intercom, Cloudflare) are reported with low confidence and low severity',
      ],
      limitations: [
        'Scripts injected by tag managers or other scripts at runtime are not visible.',
        'Whether the `integrity` hash matches the current file is not verified.',
        'Dynamic script URLs are handled by NGB005 (untrusted script loading).',
      ],
      falsePositives: [
        'Version-pinned URLs on a CDN you control are still reported; SRI is cheap insurance there too.',
      ],
      remediation:
        'Prefer bundling dependencies through npm. For CDN files, pin an exact version and add `integrity="sha384-…" crossorigin="anonymous"`. For providers that cannot support SRI, restrict them with a strict CSP allowlist and keep them off sensitive pages (checkout, login).',
      example: {
        unsafe: `<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"></script>`,
        safe: `<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"
        integrity="sha384-…" crossorigin="anonymous"></script>`,
      },
      references: [
        { title: 'MDN — Subresource Integrity', url: 'https://developer.mozilla.org/docs/Web/Security/Subresource_Integrity' },
        { title: 'OWASP — Third Party JavaScript Management', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Third_Party_Javascript_Management_Cheat_Sheet.html' },
      ],
    },
  },
  analyze(ctx) {
    const t = ctx.ts;
    const findings: RuleFinding[] = [];
    const grade = (host: string, stylesheet: boolean): { confidence: Confidence; severity: Severity } =>
      NO_SRI_HOSTS.test(host) ? { confidence: 'low', severity: 'low' } : { confidence: 'high', severity: stylesheet ? 'low' : 'medium' };

    const index = ctx.project.indexHtml;
    const html = index && ctx.readFile(index);
    if (index && html) {
      for (const tag of htmlTags(html, index, ['script', 'link'])) {
        const stylesheet = tag.name === 'link';
        if (stylesheet && !/\bstylesheet\b/i.test(tag.attrs.get('rel') ?? '')) continue;
        const url = tag.attrs.get(stylesheet ? 'href' : 'src');
        const host = externalHost(url);
        if (!host || tag.attrs.has('integrity')) continue;
        const g = grade(host, stylesheet);
        findings.push({
          location: tag.location,
          message: `${stylesheet ? 'Stylesheet' : 'Script'} from ${host} in ${relative(ctx, index)} has no integrity attribute; a compromised CDN or package can change what runs in your page.`,
          ...g,
          evidenceKind: 'pattern',
          evidence: [`${stylesheet ? 'href' : 'src'}="${url}"`, ...(g.confidence === 'low' ? ['provider serves evolving content; SRI is not applicable — restrict it with CSP instead'] : [])],
        });
      }
    }

    // Script elements created in code with a constant external src.
    const scripts = new Map<ts.Symbol, { node: ts.Node; src?: string; integrity: boolean }>();
    const symOf = (e: ts.Expression | undefined) => {
      if (!e) return undefined;
      const x = strip(ctx, e);
      return ctx.checker.getSymbolAtLocation(t.isPropertyAccessExpression(x) ? x.name : x);
    };
    for (const call of ctx.index.calls) {
      if (memberName(ctx, strip(ctx, call.expression)) !== 'createElement') continue;
      const tagArg = call.arguments.length === 1 ? call.arguments[0] : call.arguments[0];
      if (ctx.symbols.constantString(tagArg ?? call)?.toLowerCase() !== 'script') continue;
      const recv = receiverOf(ctx, strip(ctx, call.expression));
      if (!recv || !(is(ctx.symbols.typeOrigin(recv), 'dom', 'Document') || is(ctx.symbols.typeOrigin(recv), '@angular/core', 'Renderer2'))) continue;
      let p: ts.Node = call.parent;
      while (t.isParenthesizedExpression(p) || t.isAsExpression(p)) p = p.parent;
      const holder = t.isVariableDeclaration(p) || t.isPropertyDeclaration(p) ? p.name : t.isBinaryExpression(p) ? p.left : undefined;
      const sym = holder && symOf(holder as ts.Expression);
      if (sym) scripts.set(sym, { node: call, integrity: false });
    }
    if (scripts.size) {
      const set = (target: ts.Expression | undefined, prop: string, value: ts.Expression) => {
        const s = scripts.get(symOf(target) as ts.Symbol);
        if (!s) return;
        if (prop === 'integrity') s.integrity = true;
        if (prop === 'src') {
          const v = ctx.symbols.constantString(value);
          if (v) s.src = v;
        }
      };
      for (const a of ctx.index.assignments) {
        const prop = memberName(ctx, a.left);
        if (prop) set(receiverOf(ctx, a.left), prop, a.right);
      }
      for (const call of ctx.index.calls) {
        if (memberName(ctx, strip(ctx, call.expression)) !== 'setAttribute') continue;
        const a = call.arguments;
        // el.setAttribute(name, v) or renderer.setAttribute(el, name, v)
        const [el, key, value] = a.length >= 3 ? [a[0], a[1], a[2]] : [receiverOf(ctx, strip(ctx, call.expression)), a[0], a[1]];
        const k = key && ctx.symbols.constantString(key)?.toLowerCase();
        if (k && value) set(el, k, value);
      }
      for (const s of scripts.values()) {
        const host = externalHost(s.src);
        if (!host || s.integrity) continue;
        findings.push({
          node: s.node,
          message: `Script element loads ${host} without integrity; a compromised CDN or package can change what runs in your page.`,
          confidence: 'low',
          severity: grade(host, false).severity,
          evidenceKind: 'pattern',
          evidence: [`src = ${s.src}`, 'no integrity assignment found for this element'],
        });
      }
    }
    return findings;
  },
});
