import type * as ts from 'typescript';
import { defineRule, type AnalysisContext, type RuleFinding, type TaintFlow } from '@ngbastion/plugin-api';
import { constantPrefix, flowEvidence, hasFixedOrigin, importedFrom, is, memberName, receiverOf, sinkStep, strip } from '../shared/common.js';
import { objectProp } from '../shared/http.js';

/** `<base>` elements: typed `HTMLBaseElement`, `querySelector('base')`, `createElement('base')`. */
function isBaseElement(ctx: AnalysisContext, e: ts.Expression): boolean {
  const t = ctx.ts;
  const x = strip(ctx, e);
  if (is(ctx.symbols.typeOrigin(x), 'dom', 'HTMLBaseElement')) return true;
  const fromCall = (c: ts.Expression): boolean => {
    const y = strip(ctx, c);
    if (!t.isCallExpression(y) || !y.arguments[0]) return false;
    const m = memberName(ctx, y.expression);
    const arg = ctx.symbols.constantString(y.arguments[0])?.trim().toLowerCase();
    return (m === 'querySelector' && arg === 'base') || ((m === 'createElement' || m === 'getElementsByTagName') && arg === 'base');
  };
  if (fromCall(x)) return true;
  if (t.isElementAccessExpression(x) && fromCall(x.expression)) return true;
  if (t.isIdentifier(x)) {
    const d = ctx.symbols.declarationOf(x);
    if (d && t.isVariableDeclaration(d) && d.initializer) return fromCall(d.initializer) || (t.isElementAccessExpression(strip(ctx, d.initializer)) && fromCall((strip(ctx, d.initializer) as ts.ElementAccessExpression).expression));
  }
  return false;
}

/** A constant `/segment…` or `https://host/` prefix keeps the base on a fixed origin. */
function pinned(ctx: AnalysisContext, value: ts.Expression): 'pinned' | 'slash' | undefined {
  const p = constantPrefix(ctx, value);
  if (!p) return undefined;
  if (hasFixedOrigin(p) || /^\/[^/\\]/.test(p)) return 'pinned';
  return p === '/' ? 'slash' : undefined;
}

export const ngb054 = defineRule({
  meta: {
    id: 'NGB054',
    name: 'Untrusted base URL',
    category: 'angular-xss',
    defaultSeverity: 'high',
    cwe: ['CWE-79', 'CWE-601', 'CWE-829'],
    docs: {
      description:
        "Traces untrusted data (URL, messages, storage, HTTP responses, user input) into the document base URL: the `href` of a `<base>` element (`base.href = v`, `base.setAttribute('href', v)`) and Angular's `APP_BASE_HREF` provider (`useValue` or the value returned by `useFactory`). Values with a constant same-origin path prefix (`'/' + tenant`) or a fixed `https://host/` prefix are not reported.",
      rationale:
        "The base URL decides where every relative URL resolves. An attacker-chosen `<base href=\"https://evil.example/\">` turns the application's own relative `<script src>`, lazy-loaded chunks, form actions and links into requests to the attacker — script execution without injecting a single script tag. A tainted `APP_BASE_HREF` makes router links and `Location.prepareExternalUrl()` point at another origin (open redirect, credential phishing).",
      patterns: [
        "`<base>` element: `document.querySelector('base').href = v`, `createElement('base')` + `setAttribute('href', v)`, values typed `HTMLBaseElement` — high",
        "`{ provide: APP_BASE_HREF, useValue: v }` and `useFactory: () => v` — medium",
        "Not reported: a constant prefix such as `'/app/' + x`, `` `/${tenant}` `` after a constant segment, or `https://cdn.example.com/` + x; a bare `'/' + x` prefix is reported with low confidence (`x` could start with `/`)",
        "Host / X-Forwarded-* headers are left to NGB042",
      ],
      limitations: [
        "A `<base>` element written into server-rendered HTML by string concatenation is not followed (see NGB069 for reflected server responses).",
        "`useFactory` dependencies (`deps`) are not traced into the factory's parameters.",
      ],
      falsePositives: [
        "Multi-tenant deployments that derive the base from the first path segment are reported only with a bare `/` prefix and low confidence; validate the segment against a tenant list.",
      ],
      remediation:
        "Configure the base URL from build-time configuration (`<base href>` in index.html, `--base-href`, a constant `APP_BASE_HREF`). If it must depend on the request (tenants), validate the segment against an allowlist and always prepend a constant `/` path segment so it cannot become another origin.",
      example: {
        unsafe: "{ provide: APP_BASE_HREF, useFactory: () => new URLSearchParams(location.search).get('base') ?? '/' }",
        safe: "{ provide: APP_BASE_HREF, useFactory: () => TENANTS.includes(tenantFromPath()) ? `/t/${tenantFromPath()}/` : '/' }",
      },
      references: [
        { title: 'MDN — <base>: the Document Base URL element', url: 'https://developer.mozilla.org/docs/Web/HTML/Element/base' },
        { title: 'Angular API — APP_BASE_HREF', url: 'https://angular.dev/api/common/APP_BASE_HREF' },
      ],
    },
  },
  analyze(ctx) {
    const t = ctx.ts;
    const findings: RuleFinding[] = [];
    const report = (sink: ts.Node, value: ts.Expression, what: string, severity: 'high' | 'medium') => {
      const pin = pinned(ctx, value);
      if (pin === 'pinned') return;
      const flow: TaintFlow | undefined = ctx.taint.trace(value, { context: 'resource-url' }).flows.find((f) => f.source.kind !== 'request-header');
      if (!flow) return;
      findings.push({
        node: sink,
        message: `${what} is set from untrusted data (${flow.source.description}); relative URLs can then resolve to an attacker-chosen origin.`,
        confidence: pin === 'slash' ? 'low' : flow.confidence,
        severity,
        evidenceKind: 'dataflow',
        trace: [...flow.steps, sinkStep(ctx, sink, what)],
        evidence: [...flowEvidence(flow), ...(pin === 'slash' ? ["constant prefix is only '/'; the value may start with '/' and form a protocol-relative URL"] : [])],
      });
    };

    for (const a of ctx.index.assignments) {
      if (a.operatorToken.kind !== t.SyntaxKind.EqualsToken || memberName(ctx, a.left) !== 'href') continue;
      const recv = receiverOf(ctx, a.left);
      if (recv && isBaseElement(ctx, recv)) report(a, a.right, '<base href>', 'high');
    }
    for (const call of ctx.index.calls) {
      if (memberName(ctx, call.expression) !== 'setAttribute' || call.arguments.length < 2) continue;
      if (ctx.symbols.constantString(call.arguments[0]!)?.toLowerCase() !== 'href') continue;
      const recv = receiverOf(ctx, call.expression);
      if (recv && isBaseElement(ctx, recv)) report(call, call.arguments[1]!, '<base href>', 'high');
    }

    const visit = (n: ts.Node): void => {
      if (t.isObjectLiteralExpression(n)) {
        const provide = objectProp(ctx, n, 'provide');
        const token = provide && strip(ctx, provide);
        const isToken = token && (is(ctx.symbols.typeOrigin(token), '@angular/common', 'APP_BASE_HREF') || importedFrom(ctx, token, '@angular/common', 'APP_BASE_HREF'));
        if (isToken) {
          const useValue = objectProp(ctx, n, 'useValue');
          if (useValue) report(useValue, useValue, 'APP_BASE_HREF', 'medium');
          const useFactory = objectProp(ctx, n, 'useFactory');
          const fn = useFactory && ctx.flow.resolveFunction(useFactory);
          const body = fn && (fn as { body?: ts.Node }).body;
          if (body && !t.isBlock(body)) report(body as ts.Expression, body as ts.Expression, 'APP_BASE_HREF', 'medium');
          else if (body) {
            const rets: ts.Expression[] = [];
            const walk = (x: ts.Node): void => {
              if (t.isFunctionLike(x)) return;
              if (t.isReturnStatement(x) && x.expression) rets.push(x.expression);
              t.forEachChild(x, walk);
            };
            t.forEachChild(body, walk);
            for (const r of rets) report(r, r, 'APP_BASE_HREF', 'medium');
          }
        }
      }
      t.forEachChild(n, visit);
    };
    for (const sf of ctx.sourceFiles) visit(sf);
    return findings;
  },
});
