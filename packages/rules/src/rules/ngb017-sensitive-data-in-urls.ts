import type * as ts from 'typescript';
import { defineRule, type AnalysisContext, type Confidence, type RuleFinding } from '@ngbastion/plugin-api';
import { is, memberName, receiverOf, strip } from '../shared/common.js';
import { classifyName, describeEvidence, isRedacted, sensitivityOf, type SensitivityEvidence } from '../shared/sensitivity.js';
import { confidenceOf, strongest } from './ngb016-sensitive-data-logging.js';

/** OAuth 2.0 / OIDC parameters that legitimately travel in URLs. */
const PROTOCOL_PARAMS = new Set([
  'code', 'state', 'nonce', 'client_id', 'redirect_uri', 'code_challenge', 'code_challenge_method', 'response_type',
  'response_mode', 'scope', 'prompt', 'login_hint', 'id_token_hint', 'post_logout_redirect_uri', 'ui_locales', 'acr_values',
]);
const HTTP = '@angular/common/http';
const HTTP_OPTIONS_INDEX: Record<string, number> = { get: 1, delete: 1, head: 1, options: 1, jsonp: -1, post: 2, put: 2, patch: 2, request: 2 };

interface Placement {
  value: ts.Expression;
  /** Query/fragment parameter name, when known. */
  param?: string;
  where: string;
}

/** Splits a URL-building expression into its dynamic parts with their parameter names. */
function urlParts(ctx: AnalysisContext, expr: ts.Expression, depth = 0): Placement[] {
  const t = ctx.ts;
  const e = strip(ctx, expr);
  if (depth < 2 && t.isIdentifier(e)) {
    const d = ctx.symbols.declarationOf(e);
    if (d && t.isVariableDeclaration(d) && d.initializer) return urlParts(ctx, d.initializer, depth + 1);
    return [];
  }
  const pieces: (string | ts.Expression)[] = [];
  const flatten = (x: ts.Expression) => {
    const s = strip(ctx, x);
    if (t.isBinaryExpression(s) && s.operatorToken.kind === t.SyntaxKind.PlusToken) {
      flatten(s.left);
      flatten(s.right);
      return;
    }
    if (t.isTemplateExpression(s)) {
      pieces.push(s.head.text);
      for (const span of s.templateSpans) pieces.push(span.expression, span.literal.text);
      return;
    }
    const c = ctx.symbols.constantString(s);
    pieces.push(c ?? s);
  };
  flatten(e);
  if (pieces.every((p) => typeof p === 'string')) return [];
  const out: Placement[] = [];
  let text = '';
  for (const p of pieces) {
    if (typeof p === 'string') {
      text += p;
      continue;
    }
    const m = /[?&#;]([\w.[\]-]+)=$/.exec(text);
    const inQuery = /[?#]/.test(text);
    out.push({ value: p, ...(m ? { param: m[1]! } : {}), where: m ? `URL parameter '${m[1]}'` : inQuery ? 'the URL query/fragment' : 'the URL path' });
    text += '\u0000';
  }
  return out;
}

function objectParts(ctx: AnalysisContext, expr: ts.Expression | undefined, where: string): Placement[] {
  const t = ctx.ts;
  if (!expr) return [];
  const e = strip(ctx, expr);
  if (!t.isObjectLiteralExpression(e)) return [];
  return e.properties.flatMap((p): Placement[] => {
    if (t.isPropertyAssignment(p) && (t.isIdentifier(p.name) || t.isStringLiteral(p.name))) {
      return [{ value: p.initializer, param: p.name.text, where: `${where} '${p.name.text}'` }];
    }
    if (t.isShorthandPropertyAssignment(p)) return [{ value: p.name, param: p.name.text, where: `${where} '${p.name.text}'` }];
    return [];
  });
}

function propertyOf(ctx: AnalysisContext, obj: ts.Expression | undefined, name: string): ts.Expression | undefined {
  const t = ctx.ts;
  const e = obj && strip(ctx, obj);
  if (!e || !t.isObjectLiteralExpression(e)) return undefined;
  for (const p of e.properties) {
    if (t.isPropertyAssignment(p) && p.name.getText().replace(/['"]/g, '') === name) return p.initializer;
    if (t.isShorthandPropertyAssignment(p) && p.name.text === name) return p.name;
  }
  return undefined;
}

export const ngb017 = defineRule({
  meta: {
    id: 'NGB017',
    name: 'Sensitive data in URLs',
    category: 'sensitive-data',
    defaultSeverity: 'high',
    cwe: ['CWE-598'],
    docs: {
      description:
        'Reports credentials (access tokens, passwords, API keys, session IDs) and payment data (card number, CVV) placed into URL paths, query parameters or fragments when building HTTP requests, navigation targets or query-parameter objects. OAuth 2.0 / OpenID Connect protocol parameters (`code`, `state`, `nonce`, `client_id`, `redirect_uri`, `code_challenge`, `id_token_hint`, …) are not reported.',
      rationale:
        'URLs are written to browser history, server and proxy access logs, analytics tools and the `Referer` header sent to third parties. Secrets in URLs leak through all of these channels and are hard to revoke after the fact.',
      patterns: [
        'Template literals and `+` concatenation building URLs: `/api?token=${token}` (parameter name from the preceding `name=`), dynamic path segments',
        '`HttpClient.get/post/put/patch/delete/request(url, …, { params: { … } })`, `fetch(url)`',
        '`new HttpParams().set/append(name, value)`, `new HttpParams({ fromObject: { … } })`, `URLSearchParams.set/append`, `new URLSearchParams({ … })`, `url.searchParams.set(…)`',
        '`router.navigate(commands, { queryParams: { … } })`, `router.navigateByUrl(url)`, `window.open(url)`, `location.assign/replace(url)`, `location.href = url`',
        'URL variables are followed through up to two `const`/`let` initializers',
      ],
      limitations: [
        'URLs assembled in helper functions or with `URL`/`HttpParams` objects passed between functions are not reconstructed.',
        'Values are judged by names (parameter, variable, property, type) and traced names; an opaque variable like `x` carrying a token is missed.',
      ],
      falsePositives: [
        'Protocols that require a token in the URL (e.g. signed download links, password-reset links received by e-mail) are reported; document an exception with the justification.',
        'Opaque payment references (`paymentToken`, `orderId`) are intentionally not treated as payment data.',
      ],
      remediation:
        'Send secrets in request headers (`Authorization`) or a POST body. For one-time links, use short-lived single-use tokens exchanged server-side and remove them from the address bar with `history.replaceState()` after use.',
      example: {
        unsafe: `this.http.get(\`/api/report?access_token=\${this.auth.accessToken}\`);`,
        safe: `this.http.get('/api/report', { headers: { Authorization: \`Bearer \${this.auth.accessToken}\` } });`,
      },
      references: [{ title: 'OWASP — Information exposure through query strings', url: 'https://owasp.org/www-community/vulnerabilities/Information_exposure_through_query_strings_in_url' }],
    },
  },
  analyze(ctx) {
    const t = ctx.ts;
    const findings: RuleFinding[] = [];
    const seen = new Set<string>();

    const check = (sink: ts.Node, label: string, placements: Placement[]) => {
      for (const p of placements) {
        if (p.param && PROTOCOL_PARAMS.has(p.param.toLowerCase())) continue;
        const trace = ctx.taint.trace(p.value, { context: 'generic' });
        if (isRedacted(ctx, p.value, trace)) continue;
        const evidence: SensitivityEvidence[] = [];
        const byParam = p.param ? classifyName(p.param) : undefined;
        if (byParam) evidence.push({ match: byParam, via: 'name' });
        evidence.push(...sensitivityOf(ctx, p.value, trace).filter((e) => e.via !== 'type'));
        const top = strongest(evidence);
        if (!top) continue;
        const key = `${p.value.getSourceFile().fileName}:${p.value.getStart()}`;
        if (seen.has(key)) continue;
        seen.add(key);
        const confidence: Confidence = confidenceOf(top);
        const what = top.match.category === 'payment' ? 'Payment data' : 'A credential';
        findings.push({
          node: p.value,
          message: `${what} ('${top.match.term}') is placed in ${p.where} of ${label}; URLs leak through history, logs and Referer headers.`,
          confidence,
          evidenceKind: 'pattern',
          evidence: [`sink: ${label}`, ...evidence.slice(0, 4).map(describeEvidence)],
        });
      }
    };

    for (const call of ctx.index.calls) {
      const callee = strip(ctx, call.expression);
      const name = memberName(ctx, callee) ?? (t.isIdentifier(callee) ? callee.text : undefined);
      const recv = receiverOf(ctx, callee);
      const info = ctx.symbols.callee(call);
      if (!name || !info || info.declaration) continue;
      const ro = recv ? ctx.symbols.typeOrigin(recv) : undefined;

      if (recv && is(ro, HTTP, 'HttpClient') && Object.hasOwn(HTTP_OPTIONS_INDEX, name)) {
        const urlArg = call.arguments[name === 'request' ? 1 : 0];
        if (urlArg) check(call, `HttpClient.${name}()`, urlParts(ctx, urlArg));
        const optIdx = HTTP_OPTIONS_INDEX[name]!;
        if (optIdx >= 0) check(call, `HttpClient.${name}() params`, objectParts(ctx, propertyOf(ctx, call.arguments[optIdx], 'params'), 'query parameter'));
      } else if (recv && (is(ro, HTTP, 'HttpParams') || is(ro, 'dom', 'URLSearchParams')) && (name === 'set' || name === 'append') && call.arguments[1]) {
        const param = ctx.symbols.constantString(call.arguments[0]!);
        check(call, `${ro!.name}.${name}()`, [{ value: call.arguments[1], ...(param ? { param } : {}), where: `query parameter '${param ?? '?'}'` }]);
      } else if (recv && is(ro, '@angular/router', 'Router')) {
        if (name === 'navigateByUrl' && call.arguments[0]) check(call, 'Router.navigateByUrl()', urlParts(ctx, call.arguments[0]));
        if (name === 'navigate') {
          const cmds = call.arguments[0] && strip(ctx, call.arguments[0]);
          if (cmds && t.isArrayLiteralExpression(cmds)) {
            check(call, 'Router.navigate()', cmds.elements.filter((el) => !t.isStringLiteralLike(el) && !t.isSpreadElement(el)).map((el) => ({ value: el, where: 'the route path' })));
          }
          check(call, 'Router.navigate()', objectParts(ctx, propertyOf(ctx, call.arguments[1], 'queryParams'), 'query parameter'));
        }
      } else if (!recv && name === 'fetch' && call.arguments[0]) {
        check(call, 'fetch()', urlParts(ctx, call.arguments[0]));
      } else if (name === 'open' && call.arguments[0] && (!recv || is(ro, 'dom', 'Window'))) {
        check(call, 'window.open()', urlParts(ctx, call.arguments[0]));
      } else if ((name === 'assign' || name === 'replace') && recv && is(ro, 'dom', 'Location') && call.arguments[0]) {
        check(call, `location.${name}()`, urlParts(ctx, call.arguments[0]));
      }
    }
    for (const n of ctx.index.newExpressions) {
      const o = ctx.symbols.typeOrigin(n);
      const arg = n.arguments?.[0];
      if (is(o, 'dom', 'URLSearchParams')) check(n, 'new URLSearchParams()', objectParts(ctx, arg, 'query parameter'));
      if (is(o, HTTP, 'HttpParams')) check(n, 'new HttpParams()', objectParts(ctx, propertyOf(ctx, arg, 'fromObject'), 'query parameter'));
    }
    for (const a of ctx.index.assignments) {
      const prop = memberName(ctx, a.left);
      const target = prop ? receiverOf(ctx, a.left) : strip(ctx, a.left);
      const to = target ? ctx.symbols.typeOrigin(target) : undefined;
      const isLocationHref = (prop === 'href' || prop === 'hash' || prop === 'search') && is(to, 'dom', 'Location');
      const isLocation = prop === 'location' && is(ctx.symbols.typeOrigin(a.left), 'dom', 'Location');
      if (isLocationHref || isLocation) check(a, `location${prop === 'location' ? '' : `.${prop}`} assignment`, urlParts(ctx, a.right));
    }
    return findings;
  },
});
