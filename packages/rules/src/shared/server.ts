import type * as ts from 'typescript';
import type { AnalysisContext } from '@ngbastion/plugin-api';
import { memberName, receiverOf, strip } from './common.js';

/** `child_process` → also `node:child_process`. */
export function nodeModules(...names: string[]): string[] {
  return names.flatMap((n) => (n.startsWith('node:') ? [n] : [n, `node:${n}`]));
}

/** Module name of `require('x')` (possibly wrapped: `require('x').y` is handled by the caller). */
function requiredModule(ctx: AnalysisContext, e: ts.Expression): string | undefined {
  const t = ctx.ts;
  const x = strip(ctx, e);
  if (t.isCallExpression(x) && t.isIdentifier(x.expression) && x.expression.text === 'require' && x.arguments[0] && t.isStringLiteralLike(x.arguments[0])) return x.arguments[0].text;
  return undefined;
}

/** Module an identifier was bound to through `const x = require('m')` / `const { f } = require('m')`. */
function requireBinding(ctx: AnalysisContext, id: ts.Identifier): string | undefined {
  const t = ctx.ts;
  const d = ctx.symbols.declarationOf(id);
  if (!d) return undefined;
  if (t.isVariableDeclaration(d) && d.initializer) return requiredModule(ctx, d.initializer);
  if (t.isBindingElement(d)) {
    const decl = d.parent.parent;
    if (t.isVariableDeclaration(decl) && decl.initializer) return requiredModule(ctx, decl.initializer);
  }
  return undefined;
}

/**
 * Call of a function exported by one of `modules`: `exec()` (named import / destructured require),
 * `cp.exec()` (namespace, default or `require()` binding) and `require('m').exec()`.
 */
export function moduleCall(ctx: AnalysisContext, call: ts.CallExpression | ts.NewExpression, modules: readonly string[], names: readonly string[]): string | undefined {
  const t = ctx.ts;
  const callee = strip(ctx, call.expression);
  const name = t.isIdentifier(callee) ? callee.text : memberName(ctx, callee);
  if (!name) return undefined;
  const info = ctx.symbols.callee(call);
  if (info?.declaration) return undefined;
  let fn = info?.name ?? name;
  if (!names.includes(fn) && t.isIdentifier(callee)) {
    // const { exec: run } = require('child_process')
    const d = ctx.symbols.declarationOf(callee);
    if (d && t.isBindingElement(d) && d.propertyName && t.isIdentifier(d.propertyName)) fn = d.propertyName.text;
  }
  if (!names.includes(fn)) return undefined;
  if (info?.origin && modules.includes(info.origin.module)) return fn;
  if (info?.receiver && modules.includes(info.receiver.module) && ['*', 'default', fn].includes(info.receiver.name)) return fn;
  if (t.isIdentifier(callee)) {
    const m = requireBinding(ctx, callee);
    return m && modules.includes(m) ? fn : undefined;
  }
  const recv = receiverOf(ctx, callee);
  if (!recv) return undefined;
  const r = strip(ctx, recv);
  const m = requiredModule(ctx, r) ?? (t.isIdentifier(r) ? requireBinding(ctx, r) : undefined);
  return m && modules.includes(m) ? fn : undefined;
}

const EXPRESS = ['express', 'express-serve-static-core'];
const NODE_HTTP = nodeModules('http', 'http2', 'https');

/**
 * Server response object: Express `Response`, Node `ServerResponse`; untyped `res` / `response`
 * parameters that directly follow a `req` / `request` parameter.
 */
export function isServerResponse(ctx: AnalysisContext, expr: ts.Expression): boolean {
  const t = ctx.ts;
  const e = strip(ctx, expr);
  const o = ctx.symbols.typeOrigin(e);
  if (o && (EXPRESS.includes(o.module) && o.name === 'Response' || NODE_HTTP.includes(o.module) && ['ServerResponse', 'Http2ServerResponse'].includes(o.name))) return true;
  if (o && o.name !== 'any') return false;
  if (!t.isIdentifier(e) || !/^res(ponse)?$/.test(e.text)) return false;
  const d = ctx.symbols.declarationOf(e);
  if (!d || !t.isParameter(d) || d.type || !t.isFunctionLike(d.parent)) return false;
  const params = d.parent.parameters;
  const i = params.indexOf(d);
  const prev = params[i - 1];
  return i > 0 && !!prev && t.isIdentifier(prev.name) && /^req(uest)?$/.test(prev.name.text);
}

/** Server request object (same conventions as `isServerResponse`). */
export function isServerRequest(ctx: AnalysisContext, expr: ts.Expression): boolean {
  const t = ctx.ts;
  const e = strip(ctx, expr);
  const o = ctx.symbols.typeOrigin(e);
  if (o && (EXPRESS.includes(o.module) && o.name === 'Request' || NODE_HTTP.includes(o.module) && ['IncomingMessage', 'Http2ServerRequest'].includes(o.name))) return true;
  if (o && o.name !== 'any') return false;
  if (!t.isIdentifier(e) || !/^req(uest)?$/.test(e.text)) return false;
  const d = ctx.symbols.declarationOf(e);
  if (!d || !t.isParameter(d) || d.type || !t.isFunctionLike(d.parent)) return false;
  const params = d.parent.parameters;
  const next = params[params.indexOf(d) + 1];
  return !!next && t.isIdentifier(next.name) && /^res(ponse)?$/.test(next.name.text);
}

/** Method call on a server response: `res.send(…)`, `res.status(500).json(…)` (chains are followed). */
export function responseCall(ctx: AnalysisContext, call: ts.CallExpression, methods: readonly string[]): boolean {
  const t = ctx.ts;
  const callee = strip(ctx, call.expression);
  const name = memberName(ctx, callee);
  if (!name || !methods.includes(name)) return false;
  let recv = receiverOf(ctx, callee);
  // res.status(500).send(…), res.type('html').send(…)
  while (recv && t.isCallExpression(strip(ctx, recv)) && ['status', 'type', 'set', 'header', 'append', 'cookie', 'clearCookie', 'vary', 'location'].includes(memberName(ctx, (strip(ctx, recv) as ts.CallExpression).expression) ?? '')) {
    recv = receiverOf(ctx, (strip(ctx, recv) as ts.CallExpression).expression);
  }
  return !!recv && isServerResponse(ctx, recv);
}

/** `req.headers.origin`, `req.headers['origin']`, `req.get('origin')`, `req.header('Origin')` for the given header names. */
export function requestHeaderRead(ctx: AnalysisContext, expr: ts.Expression, headers: readonly string[]): string | undefined {
  const t = ctx.ts;
  const e = strip(ctx, expr);
  const wanted = (h: string | undefined) => (h && headers.includes(h.toLowerCase()) ? h.toLowerCase() : undefined);
  if (t.isPropertyAccessExpression(e) || t.isElementAccessExpression(e)) {
    const obj = receiverOf(ctx, e);
    if (obj && memberName(ctx, obj) === 'headers' && isServerRequest(ctx, receiverOf(ctx, obj)!)) return wanted(memberName(ctx, e));
  }
  if (t.isCallExpression(e) && e.arguments[0]) {
    const callee = strip(ctx, e.expression);
    const m = memberName(ctx, callee);
    const recv = receiverOf(ctx, callee);
    if ((m === 'get' || m === 'header') && recv && isServerRequest(ctx, recv)) return wanted(ctx.symbols.constantString(e.arguments[0]));
  }
  return undefined;
}

/** Files that run on the server: SSR entry points and files importing Node / Express modules. */
export function isServerFile(ctx: AnalysisContext, sf: ts.SourceFile): boolean {
  if (/(^|[/\\])(server|main\.server|app\.config\.server)\.[cm]?[jt]s$/.test(sf.fileName) || /[/\\](server|backend)[/\\]/.test(sf.fileName)) return true;
  return /\bfrom\s+['"](node:[\w/]+|express|fs|child_process|http|https|crypto|path)['"]|\brequire\(\s*['"](node:[\w/]+|express|fs|child_process|http|https|crypto)['"]\s*\)/.test(sf.text);
}

/** Expression reads a server request header / body / query / cookies (directly or via a `const`). */
export function requestDerived(ctx: AnalysisContext, e: ts.Expression, depth = 0): string | undefined {
  const t = ctx.ts;
  let found: string | undefined;
  const visit = (n: ts.Node): void => {
    if (found) return;
    if (t.isPropertyAccessExpression(n) || t.isElementAccessExpression(n)) {
      const name = memberName(ctx, n as ts.Expression);
      const recv = receiverOf(ctx, n as ts.Expression);
      if (recv && name && ['headers', 'body', 'query', 'cookies', 'params'].includes(name) && isServerRequest(ctx, recv)) {
        found = `request ${name}`;
        return;
      }
    }
    if (t.isCallExpression(n)) {
      const callee = strip(ctx, n.expression);
      const m = memberName(ctx, callee);
      const recv = receiverOf(ctx, callee);
      if (recv && (m === 'get' || m === 'header') && isServerRequest(ctx, recv)) {
        found = `request header ${n.arguments[0] ? ctx.symbols.constantString(n.arguments[0]) ?? '' : ''}`.trim();
        return;
      }
    }
    if (t.isIdentifier(n) && depth < 3) {
      const d = ctx.symbols.declarationOf(n);
      if (d && t.isVariableDeclaration(d) && d.initializer) found = requestDerived(ctx, d.initializer, depth + 1);
      else if (d && t.isBindingElement(d)) {
        const decl = d.parent.parent;
        if (t.isVariableDeclaration(decl) && decl.initializer) found = requestDerived(ctx, decl.initializer, depth + 1);
      }
      return;
    }
    t.forEachChild(n, visit);
  };
  visit(e);
  return found;
}
