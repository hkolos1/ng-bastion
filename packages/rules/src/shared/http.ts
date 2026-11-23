import type * as ts from 'typescript';
import type { AnalysisContext } from '@ngbastion/plugin-api';
import { is, isGlobalCall, memberName, receiverOf, strip } from './common.js';

export const HTTP_MODULE = '@angular/common/http';
const BODY_METHODS = new Set(['post', 'put', 'patch']);
const NO_BODY_METHODS = new Set(['get', 'delete', 'head', 'options', 'jsonp']);
const AUTH_HEADER = /^(authorization|proxy-authorization|x-api-key|x-auth-token|x-access-token|api-key|apikey|cookie)$/i;

/** One outgoing request whose destination is visible in code. */
export interface RequestCall {
  node: ts.CallExpression | ts.NewExpression;
  /** e.g. `HttpClient.post()`, `fetch()`, `new WebSocket()`. */
  api: string;
  /** HTTP method when known (lowercase). */
  method?: string;
  url: ts.Expression;
  body?: ts.Expression;
  options?: ts.Expression;
  transport: 'http' | 'websocket' | 'event-stream' | 'beacon';
  /** `withCredentials: true` / `credentials: 'include'`. */
  credentials: boolean;
  /** An Authorization / API-key header is set on this call. */
  authHeader: boolean;
}

/** Property initializer of an object literal (`{ key: v }` or shorthand `{ key }`). */
export function objectProp(ctx: AnalysisContext, obj: ts.Expression | undefined, name: string): ts.Expression | undefined {
  const t = ctx.ts;
  const o = obj && strip(ctx, obj);
  if (!o || !t.isObjectLiteralExpression(o)) return undefined;
  for (const p of o.properties) {
    const key = p.name && (t.isIdentifier(p.name) || t.isStringLiteralLike(p.name)) ? p.name.text : undefined;
    if (key !== name) continue;
    if (t.isPropertyAssignment(p)) return p.initializer;
    if (t.isShorthandPropertyAssignment(p)) return p.name;
  }
  return undefined;
}

/** Object literal behind an expression (inline or a `const` initializer). */
export function objectLiteral(ctx: AnalysisContext, e: ts.Expression | undefined): ts.ObjectLiteralExpression | undefined {
  const t = ctx.ts;
  if (!e) return undefined;
  const x = strip(ctx, e);
  if (t.isObjectLiteralExpression(x)) return x;
  if (t.isIdentifier(x)) {
    const d = ctx.symbols.declarationOf(x);
    if (d && t.isVariableDeclaration(d) && d.initializer && t.isObjectLiteralExpression(strip(ctx, d.initializer))) return strip(ctx, d.initializer) as ts.ObjectLiteralExpression;
  }
  return undefined;
}

/** Header names set anywhere inside an options/headers expression (object keys, `.set/.append('X', …)`, `new HttpHeaders({…})`). */
export function headerNames(ctx: AnalysisContext, e: ts.Expression | undefined): string[] {
  const t = ctx.ts;
  const out: string[] = [];
  if (!e) return out;
  const visit = (n: ts.Node): void => {
    if (t.isPropertyAssignment(n) || t.isShorthandPropertyAssignment(n)) {
      if (n.name && (t.isIdentifier(n.name) || t.isStringLiteralLike(n.name))) out.push(n.name.text);
    }
    if (t.isCallExpression(n) && ['set', 'append'].includes(memberName(ctx, n.expression) ?? '') && n.arguments[0]) {
      const k = ctx.symbols.constantString(n.arguments[0]);
      if (k) out.push(k);
    }
    t.forEachChild(n, visit);
  };
  const lit = objectLiteral(ctx, e);
  visit(lit ?? e);
  return out;
}

function credentialsFlag(ctx: AnalysisContext, options: ts.Expression | undefined): boolean {
  const o = objectLiteral(ctx, options);
  if (!o) return false;
  const wc = objectProp(ctx, o, 'withCredentials');
  if (wc && strip(ctx, wc).kind === ctx.ts.SyntaxKind.TrueKeyword) return true;
  const c = objectProp(ctx, o, 'credentials');
  return !!c && ctx.symbols.constantString(c) === 'include';
}

/**
 * Outgoing requests: `HttpClient` methods, `fetch()`, `XMLHttpRequest.open()`, `navigator.sendBeacon()`,
 * `new EventSource()`, `new WebSocket()` and RxJS `webSocket()`.
 */
export function requestCalls(ctx: AnalysisContext): RequestCall[] {
  const t = ctx.ts;
  const out: RequestCall[] = [];
  const auth = (o: ts.Expression | undefined) => headerNames(ctx, o).some((h) => AUTH_HEADER.test(h));
  for (const call of ctx.index.calls) {
    const info = ctx.symbols.callee(call);
    if (!info || info.declaration) continue;
    const name = info.name;
    const a = call.arguments;
    const recv = receiverOf(ctx, strip(ctx, call.expression));
    if (is(info.receiver, HTTP_MODULE, 'HttpClient') && a[0]) {
      if (name === 'request' && a[1]) {
        const method = ctx.symbols.constantString(a[0])?.toLowerCase();
        out.push({ node: call, api: 'HttpClient.request()', ...(method ? { method } : {}), url: a[1], ...(objectProp(ctx, a[2], 'body') ? { body: objectProp(ctx, a[2], 'body')! } : {}), ...(a[2] ? { options: a[2] } : {}), transport: 'http', credentials: credentialsFlag(ctx, a[2]), authHeader: auth(objectProp(ctx, a[2], 'headers')) });
      } else if (BODY_METHODS.has(name) || NO_BODY_METHODS.has(name)) {
        const options = BODY_METHODS.has(name) ? a[2] : a[1];
        out.push({ node: call, api: `HttpClient.${name}()`, method: name, url: a[0], ...(BODY_METHODS.has(name) && a[1] ? { body: a[1] } : {}), ...(options ? { options } : {}), transport: 'http', credentials: credentialsFlag(ctx, options), authHeader: auth(objectProp(ctx, options, 'headers')) });
      }
    } else if (name === 'fetch' && a[0] && (recv ? is(info.receiver, 'dom', 'Window') || /^(window|globalThis|self)$/.test(strip(ctx, recv).getText()) : isGlobalCall(info, 'fetch'))) {
      const method = ctx.symbols.constantString(objectProp(ctx, objectLiteral(ctx, a[1]), 'method') ?? a[0])?.toLowerCase();
      const body = objectProp(ctx, objectLiteral(ctx, a[1]), 'body');
      out.push({ node: call, api: 'fetch()', method: method && /^[a-z]+$/.test(method) ? method : 'get', url: a[0], ...(body ? { body } : {}), ...(a[1] ? { options: a[1] } : {}), transport: 'http', credentials: credentialsFlag(ctx, a[1]), authHeader: auth(objectProp(ctx, objectLiteral(ctx, a[1]), 'headers')) });
    } else if (name === 'open' && a[1] && is(info.receiver, 'dom', 'XMLHttpRequest')) {
      const method = ctx.symbols.constantString(a[0]!)?.toLowerCase();
      out.push({ node: call, api: 'XMLHttpRequest.open()', ...(method ? { method } : {}), url: a[1], transport: 'http', credentials: false, authHeader: false });
    } else if (name === 'sendBeacon' && a[0] && is(info.receiver, 'dom', 'Navigator')) {
      out.push({ node: call, api: 'navigator.sendBeacon()', method: 'post', url: a[0], ...(a[1] ? { body: a[1] } : {}), transport: 'beacon', credentials: true, authHeader: false });
    } else if (name === 'webSocket' && t.isIdentifier(strip(ctx, call.expression)) && a[0] && (!info.origin || info.origin.module.startsWith('rxjs'))) {
      const url = objectProp(ctx, a[0], 'url') ?? a[0];
      out.push({ node: call, api: 'webSocket() (rxjs)', url, transport: 'websocket', credentials: true, authHeader: false });
    }
  }
  for (const n of ctx.index.newExpressions) {
    const callee = strip(ctx, n.expression);
    const ctor = t.isIdentifier(callee) ? callee.text : memberName(ctx, callee);
    const arg = n.arguments?.[0];
    if (!arg || (ctor !== 'WebSocket' && ctor !== 'EventSource')) continue;
    const decl = ctx.symbols.declarationOf(callee);
    if (decl && ctx.symbols.typeOrigin(callee)?.module !== 'dom' && !decl.getSourceFile().isDeclarationFile) continue;
    if (ctor === 'WebSocket') out.push({ node: n, api: 'new WebSocket()', url: arg, transport: 'websocket', credentials: true, authHeader: false });
    else out.push({ node: n, api: 'new EventSource()', method: 'get', url: arg, transport: 'event-stream', credentials: credentialsFlag(ctx, n.arguments?.[1]), authHeader: false });
  }
  return out;
}

export type UrlPart = { text: string; expr?: undefined } | { expr: ts.Expression; text?: undefined };

/** Splits a URL built by template literal or `+` concatenation into ordered constant and dynamic parts. */
export function urlParts(ctx: AnalysisContext, e: ts.Expression, depth = 0): UrlPart[] {
  const t = ctx.ts;
  const x = strip(ctx, e);
  if (t.isTemplateExpression(x)) {
    const parts: UrlPart[] = [];
    if (x.head.text) parts.push({ text: x.head.text });
    for (const s of x.templateSpans) {
      parts.push(...urlParts(ctx, s.expression, depth + 1));
      if (s.literal.text) parts.push({ text: s.literal.text });
    }
    return parts;
  }
  if (t.isBinaryExpression(x) && x.operatorToken.kind === t.SyntaxKind.PlusToken) return [...urlParts(ctx, x.left, depth), ...urlParts(ctx, x.right, depth)];
  const constant = ctx.symbols.constantString(x);
  if (constant !== undefined) return constant ? [{ text: constant }] : [];
  if (t.isIdentifier(x) && depth < 3) {
    const d = ctx.symbols.declarationOf(x);
    if (d && t.isVariableDeclaration(d) && d.initializer && t.isVariableDeclarationList(d.parent) && d.parent.flags & t.NodeFlags.Const) {
      const inner = strip(ctx, d.initializer);
      if (t.isTemplateExpression(inner) || (t.isBinaryExpression(inner) && inner.operatorToken.kind === t.SyntaxKind.PlusToken)) return urlParts(ctx, inner, depth + 1);
    }
  }
  return [{ expr: x }];
}

/** `http://` URL that is not a loopback / local development host. */
export function isPlaintextRemote(url: string, scheme: 'http' | 'ws'): boolean {
  const m = new RegExp(`^\\s*${scheme}://([^/?#:\\s]*)`, 'i').exec(url);
  if (!m) return false;
  const host = m[1]!.toLowerCase();
  return !!host && !/^(localhost|127\.\d+\.\d+\.\d+|0\.0\.0\.0|\[::1\]|::1|[\w-]+\.localhost|[\w-]+\.local|host\.docker\.internal|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+)$/.test(host);
}
