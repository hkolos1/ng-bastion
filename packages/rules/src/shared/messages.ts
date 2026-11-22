import type * as ts from 'typescript';
import type { AnalysisContext, Guard } from '@ngbastion/plugin-api';
import { is, memberName, methodCall, receiverOf, strip } from './common.js';

/** A cross-window `message` handler registration. */
export interface MessageHandler {
  /** Where the handler is registered (call, assignment, decorator or host entry). */
  registration: ts.Node;
  how: string;
  fn: ts.SignatureDeclaration;
  /** Index of the parameter that receives the MessageEvent. */
  eventIndex: number;
  /** Callback bodies of `fromEvent(...).pipe(filter(...))` operators that run before the handler. */
  preFilters: ts.SignatureDeclaration[];
}

/** Code inside a handler that reads the message, and the call path (delegation) leading to it. */
export interface MessageRead {
  node: ts.Node;
  /** Call sites passing the event/data from the handler into a helper (one level). */
  via: ts.Node[];
}

const isWindowLike = (ctx: AnalysisContext, e: ts.Expression): boolean => {
  const o = ctx.symbols.typeOrigin(e);
  if (o) return is(o, 'dom', 'Window');
  const t = strip(ctx, e).getText();
  return /^(window|self|globalThis)$/.test(t);
};

export function findMessageHandlers(ctx: AnalysisContext): MessageHandler[] {
  const t = ctx.ts;
  const out: MessageHandler[] = [];
  const add = (registration: ts.Node, how: string, fnExpr: ts.Expression | undefined, preFilters: ts.SignatureDeclaration[] = [], eventIndex = 0) => {
    const fn = fnExpr && ctx.flow.resolveFunction(fnExpr);
    if (fn) out.push({ registration, how, fn, eventIndex, preFilters });
  };

  for (const call of ctx.index.calls) {
    const callee = strip(ctx, call.expression);
    const name = memberName(ctx, callee) ?? (t.isIdentifier(callee) ? callee.text : undefined);
    const recv = receiverOf(ctx, callee);
    if (name === 'addEventListener' && recv && call.arguments[0] && ctx.symbols.constantString(call.arguments[0]) === 'message' && isWindowLike(ctx, recv)) {
      add(call, "addEventListener('message')", call.arguments[1]);
    } else if (name === 'listen' && methodCall(ctx, call, '@angular/core', ['Renderer2'], ['listen']) && call.arguments[1]
      && ctx.symbols.constantString(call.arguments[1]) === 'message'
      && (ctx.symbols.constantString(call.arguments[0]!) === 'window' || isWindowLike(ctx, call.arguments[0]!))) {
      add(call, "Renderer2.listen('window', 'message')", call.arguments[2]);
    } else if (name === 'fromEvent' && t.isIdentifier(callee) && call.arguments[1] && ctx.symbols.constantString(call.arguments[1]) === 'message'
      && isWindowLike(ctx, call.arguments[0]!)) {
      // fromEvent(window, 'message')[.pipe(...)].subscribe(fn)
      let node: ts.Expression = call;
      const filters: ts.SignatureDeclaration[] = [];
      for (;;) {
        const pa = node.parent;
        if (!pa || !t.isPropertyAccessExpression(pa) || !t.isCallExpression(pa.parent)) break;
        const next = pa.parent;
        if (pa.name.text === 'pipe') {
          for (const op of next.arguments) {
            if (t.isCallExpression(op) && op.arguments[0]) {
              const f = ctx.flow.resolveFunction(op.arguments[0]);
              if (f) filters.push(f);
            }
          }
          node = next;
          continue;
        }
        if (pa.name.text === 'subscribe') {
          const arg = next.arguments[0];
          const fnExpr = arg && t.isObjectLiteralExpression(arg)
            ? arg.properties.find((p): p is ts.PropertyAssignment => t.isPropertyAssignment(p) && p.name.getText() === 'next')?.initializer
            : arg;
          add(call, "fromEvent(window, 'message')", fnExpr, filters);
        }
        break;
      }
    }
  }

  for (const a of ctx.index.assignments) {
    if (memberName(ctx, a.left) === 'onmessage' && isWindowLike(ctx, receiverOf(ctx, a.left)!)) add(a, 'window.onmessage', a.right);
  }

  for (const cls of ctx.index.classes) {
    for (const m of cls.members) {
      if (!t.isMethodDeclaration(m)) continue;
      for (const d of t.getDecorators(m) ?? []) {
        const c = d.expression;
        if (!t.isCallExpression(c) || !t.isIdentifier(c.expression) || c.expression.text !== 'HostListener') continue;
        if (ctx.symbols.constantString(c.arguments[0]!) !== 'window:message') continue;
        const args = c.arguments[1] && t.isArrayLiteralExpression(c.arguments[1]) ? c.arguments[1].elements.map((e) => ctx.symbols.constantString(e)) : [];
        out.push({ registration: d, how: "@HostListener('window:message')", fn: m, eventIndex: Math.max(0, args.indexOf('$event')), preFilters: [] });
      }
    }
    // @Component({ host: { '(window:message)': 'onMessage($event)' } })
    for (const d of t.getDecorators(cls) ?? []) {
      const c = d.expression;
      if (!t.isCallExpression(c) || !c.arguments[0] || !t.isObjectLiteralExpression(c.arguments[0])) continue;
      const host = c.arguments[0].properties.find((p): p is ts.PropertyAssignment => t.isPropertyAssignment(p) && p.name.getText().replace(/['"]/g, '') === 'host');
      if (!host || !t.isObjectLiteralExpression(host.initializer)) continue;
      for (const p of host.initializer.properties) {
        if (!t.isPropertyAssignment(p) || p.name.getText().replace(/['"]/g, '') !== '(window:message)') continue;
        const handler = ctx.symbols.constantString(p.initializer);
        const m = handler && /^\s*(\w+)\s*\(([^)]*)\)/.exec(handler);
        const method = m && cls.members.find((x): x is ts.MethodDeclaration => t.isMethodDeclaration(x) && x.name.getText() === m[1]);
        if (method) {
          const args = m[2]!.split(',').map((s) => s.trim());
          out.push({ registration: p, how: "host '(window:message)'", fn: method, eventIndex: Math.max(0, args.indexOf('$event')), preFilters: [] });
        }
      }
    }
  }
  return out;
}

interface Scope {
  fn: ts.SignatureDeclaration;
  eventSyms: Set<ts.Symbol>;
  dataSyms: Set<ts.Symbol>;
  via: ts.Node[];
}

function symOf(ctx: AnalysisContext, n: ts.Node): ts.Symbol | undefined {
  try {
    return ctx.checker.getSymbolAtLocation(n);
  } catch {
    return undefined;
  }
}

/** Function scopes (handler + one level of delegation) with the symbols holding the event / its data. */
export function handlerScopes(ctx: AnalysisContext, h: MessageHandler): Scope[] {
  const t = ctx.ts;
  const scopes: Scope[] = [];
  const build = (fn: ts.SignatureDeclaration, param: ts.ParameterDeclaration | undefined, kind: 'event' | 'data', via: ts.Node[]) => {
    const scope: Scope = { fn, eventSyms: new Set(), dataSyms: new Set(), via };
    if (param) {
      if (t.isIdentifier(param.name)) {
        const s = symOf(ctx, param.name);
        if (s) (kind === 'event' ? scope.eventSyms : scope.dataSyms).add(s);
      } else if (kind === 'event' && t.isObjectBindingPattern(param.name)) {
        for (const el of param.name.elements) {
          const key = (el.propertyName ?? el.name).getText();
          if (key === 'data') {
            const s = symOf(ctx, el.name);
            if (s) scope.dataSyms.add(s);
          }
        }
      }
    }
    scopes.push(scope);
    return scope;
  };
  const root = build(h.fn, h.fn.parameters[h.eventIndex], 'event', []);
  // one level of delegation: this.handle(e) / this.handle(e.data) / service.process(e.data)
  const body = (h.fn as { body?: ts.Node }).body;
  const visit = (n: ts.Node): void => {
    if (t.isCallExpression(n)) {
      const decl = ctx.symbols.callee(n)?.declaration;
      if (decl && decl !== h.fn) {
        n.arguments.forEach((arg, i) => {
          const a = strip(ctx, arg);
          const kind = isEventRef(ctx, root, a) ? 'event' : isDataRead(ctx, root, a) || isDataRef(ctx, root, a) ? 'data' : undefined;
          if (kind && decl.parameters[i]) build(decl, decl.parameters[i], kind, [n]);
        });
      }
    }
    t.forEachChild(n, visit);
  };
  if (body) visit(body);
  return scopes;
}

const isEventRef = (ctx: AnalysisContext, s: Scope, e: ts.Expression) => {
  const sym = ctx.ts.isIdentifier(e) ? symOf(ctx, e) : undefined;
  return !!sym && s.eventSyms.has(sym);
};
const isDataRef = (ctx: AnalysisContext, s: Scope, e: ts.Expression) => {
  const sym = ctx.ts.isIdentifier(e) ? symOf(ctx, e) : undefined;
  return !!sym && s.dataSyms.has(sym);
};
/** `event.data` / `event['data']`. */
const isDataRead = (ctx: AnalysisContext, s: Scope, e: ts.Expression) => memberName(ctx, e) === 'data' && isEventRef(ctx, s, strip(ctx, receiverOf(ctx, e)!));

/** Nodes in the handler (and one delegation level) that read message data. */
export function messageReads(ctx: AnalysisContext, h: MessageHandler): MessageRead[] {
  const t = ctx.ts;
  const out: MessageRead[] = [];
  for (const s of handlerScopes(ctx, h)) {
    const body = (s.fn as { body?: ts.Node }).body;
    const visit = (n: ts.Node): void => {
      if ((t.isPropertyAccessExpression(n) || t.isElementAccessExpression(n)) && isDataRead(ctx, s, n)) out.push({ node: n, via: s.via });
      // Uses of a destructured `{ data }` / data parameter.
      if (t.isIdentifier(n) && isDataRef(ctx, s, n)) out.push({ node: n, via: s.via });
      // const { data } = event;
      if (t.isVariableDeclaration(n) && t.isObjectBindingPattern(n.name) && n.initializer && isEventRef(ctx, s, strip(ctx, n.initializer))) {
        if (n.name.elements.some((el) => (el.propertyName ?? el.name).getText() === 'data')) out.push({ node: n, via: s.via });
      }
      t.forEachChild(n, visit);
    };
    if (body) visit(body);
  }
  return out;
}

/** Symbols that hold the event origin (`const o = e.origin`, `({ origin }) =>`). */
function originSymbols(ctx: AnalysisContext, s: Scope): Set<ts.Symbol> {
  const t = ctx.ts;
  const out = new Set<ts.Symbol>();
  const p = s.fn.parameters.find((x) => t.isObjectBindingPattern(x.name));
  for (const el of p && t.isObjectBindingPattern(p.name) ? p.name.elements : []) {
    if ((el.propertyName ?? el.name).getText() === 'origin') {
      const sym = symOf(ctx, el.name);
      if (sym) out.add(sym);
    }
  }
  const body = (s.fn as { body?: ts.Node }).body;
  const visit = (n: ts.Node): void => {
    if (t.isVariableDeclaration(n) && n.initializer) {
      const init = strip(ctx, n.initializer);
      if (t.isIdentifier(n.name) && memberName(ctx, init) === 'origin' && isEventRef(ctx, s, strip(ctx, receiverOf(ctx, init)!))) {
        const sym = symOf(ctx, n.name);
        if (sym) out.add(sym);
      }
      if (t.isObjectBindingPattern(n.name) && isEventRef(ctx, s, init)) {
        for (const el of n.name.elements) {
          if ((el.propertyName ?? el.name).getText() === 'origin') {
            const sym = symOf(ctx, el.name);
            if (sym) out.add(sym);
          }
        }
      }
    }
    t.forEachChild(n, visit);
  };
  if (body) visit(body);
  return out;
}

export type CheckStrength = 'strict' | 'weak';

/**
 * Classifies how a condition constrains `event.origin` (or `event.source` with `prop: 'source'`).
 * Returns the strongest *enforcing* check given the branch polarity, or undefined.
 */
export function classifyCheck(
  ctx: AnalysisContext,
  cond: ts.Expression,
  whenTrue: boolean,
  isTarget: (e: ts.Expression) => boolean,
  depth = 0,
): CheckStrength | undefined {
  const t = ctx.ts;
  const e = strip(ctx, cond);
  if (t.isPrefixUnaryExpression(e) && e.operator === t.SyntaxKind.ExclamationToken) return classifyCheck(ctx, e.operand, !whenTrue, isTarget, depth);
  if (t.isBinaryExpression(e)) {
    const op = e.operatorToken.kind;
    if (op === t.SyntaxKind.AmpersandAmpersandToken || op === t.SyntaxKind.BarBarToken) {
      // Within `a && b` executing on true, both hold; for `||` on false, both are false. Other mixes are approximated.
      const l = classifyCheck(ctx, e.left, whenTrue, isTarget, depth);
      const r = classifyCheck(ctx, e.right, whenTrue, isTarget, depth);
      return l === 'strict' || r === 'strict' ? 'strict' : l ?? r;
    }
    const eq = op === t.SyntaxKind.EqualsEqualsEqualsToken || op === t.SyntaxKind.EqualsEqualsToken;
    const neq = op === t.SyntaxKind.ExclamationEqualsEqualsToken || op === t.SyntaxKind.ExclamationEqualsToken;
    if ((eq || neq) && (isTarget(e.left) || isTarget(e.right))) {
      return (eq && whenTrue) || (neq && !whenTrue) ? 'strict' : undefined;
    }
    // allowlist.indexOf(origin) !== -1 / >= 0 / > -1
    const call = t.isCallExpression(strip(ctx, e.left)) ? strip(ctx, e.left) as ts.CallExpression : undefined;
    if (call && memberName(ctx, call.expression) === 'indexOf') {
      const recv = receiverOf(ctx, call.expression)!;
      const positive = neq || op === t.SyntaxKind.GreaterThanEqualsToken || op === t.SyntaxKind.GreaterThanToken;
      if (call.arguments[0] && isTarget(call.arguments[0])) {
        if (!(positive === whenTrue)) return undefined;
        return isStringish(ctx, recv) ? 'weak' : 'strict';
      }
      if (isTarget(recv)) return positive === whenTrue ? 'weak' : undefined;
    }
    return undefined;
  }
  if (t.isCallExpression(e)) {
    const name = memberName(ctx, e.expression) ?? (t.isIdentifier(e.expression) ? e.expression.text : undefined);
    const recv = receiverOf(ctx, e.expression);
    const arg0 = e.arguments[0];
    if (!whenTrue) return undefined;
    if (recv && isTarget(recv) && name && ['startsWith', 'endsWith', 'includes', 'match', 'search', 'indexOf'].includes(name)) return 'weak';
    if (recv && arg0 && isTarget(arg0) && (name === 'includes' || name === 'has' || name === 'some')) return isStringish(ctx, recv) ? 'weak' : 'strict';
    if (recv && arg0 && isTarget(arg0) && name === 'test') {
      const rx = strip(ctx, recv);
      if (t.isRegularExpressionLiteral(rx)) {
        const body = rx.text.slice(1, rx.text.lastIndexOf('/'));
        return body.startsWith('^') && body.endsWith('$') ? 'strict' : 'weak';
      }
      return 'weak';
    }
    // Project validator: isAllowedOrigin(e.origin) → classify its body against the parameter.
    const decl = ctx.symbols.callee(e)?.declaration;
    const idx = e.arguments.findIndex((a) => isTarget(a));
    if (decl && idx >= 0 && depth < 2) {
      const p = decl.parameters[idx];
      const psym = p && t.isIdentifier(p.name) ? symOf(ctx, p.name) : undefined;
      if (!psym) return undefined;
      const isParam = (x: ts.Expression) => {
        const y = strip(ctx, x);
        return t.isIdentifier(y) && symOf(ctx, y) === psym;
      };
      let best: CheckStrength | undefined;
      const body = (decl as { body?: ts.Node }).body;
      const exprs: ts.Expression[] = [];
      const collect = (n: ts.Node): void => {
        if (t.isReturnStatement(n) && n.expression) exprs.push(n.expression);
        t.forEachChild(n, collect);
      };
      if (body) {
        if (t.isBlock(body)) collect(body);
        else exprs.push(body as ts.Expression);
      }
      for (const x of exprs) {
        const c = classifyCheck(ctx, x, true, isParam, depth + 1);
        if (c === 'strict') return 'strict';
        best ??= c;
      }
      return best;
    }
  }
  return undefined;
}

function isStringish(ctx: AnalysisContext, e: ts.Expression): boolean {
  const type = ctx.checker.getTypeAtLocation(e);
  return !!(type.flags & ctx.ts.TypeFlags.StringLike);
}

/** Predicate: does `e` denote `event.<prop>` (or a variable holding it) within scope? */
export function propMatcher(ctx: AnalysisContext, h: MessageHandler, prop: 'origin' | 'source'): (e: ts.Expression) => boolean {
  const t = ctx.ts;
  const scopes = handlerScopes(ctx, h);
  const held = new Set<ts.Symbol>();
  if (prop === 'origin') for (const s of scopes) for (const x of originSymbols(ctx, s)) held.add(x);
  const preFilterParams = new Set(h.preFilters.map((f) => f.parameters[0] && t.isIdentifier(f.parameters[0].name) ? symOf(ctx, f.parameters[0].name) : undefined).filter(Boolean) as ts.Symbol[]);
  return (x: ts.Expression) => {
    const e = strip(ctx, x);
    if (t.isIdentifier(e)) {
      const sym = symOf(ctx, e);
      return !!sym && held.has(sym);
    }
    if (memberName(ctx, e) !== prop) return false;
    const obj = strip(ctx, receiverOf(ctx, e)!);
    if (!t.isIdentifier(obj)) return false;
    const sym = symOf(ctx, obj);
    return !!sym && (scopes.some((s) => s.eventSyms.has(sym)) || preFilterParams.has(sym));
  };
}

/** Guards that dominate a read: its own guards plus guards on the delegation call sites. */
export function guardsFor(ctx: AnalysisContext, read: MessageRead): Guard[] {
  return [read.node, ...read.via].flatMap((n) => ctx.flow.guards(n));
}

/** Strongest check on `prop` that dominates the read (pre-filters in fromEvent pipes count). */
export function readCheck(ctx: AnalysisContext, h: MessageHandler, read: MessageRead, prop: 'origin' | 'source'): CheckStrength | undefined {
  const isTarget = propMatcher(ctx, h, prop);
  let best: CheckStrength | undefined;
  const consider = (c: CheckStrength | undefined) => {
    if (c === 'strict') best = 'strict';
    else if (c && !best) best = c;
  };
  for (const g of guardsFor(ctx, read)) consider(classifyCheck(ctx, g.condition, g.whenTrue, isTarget));
  for (const f of h.preFilters) {
    const body = (f as { body?: ts.Node }).body;
    if (body && !ctx.ts.isBlock(body)) consider(classifyCheck(ctx, body as ts.Expression, true, isTarget));
    else if (body) {
      const visit = (n: ts.Node): void => {
        if (ctx.ts.isReturnStatement(n) && n.expression) consider(classifyCheck(ctx, n.expression, true, isTarget));
        ctx.ts.forEachChild(n, visit);
      };
      visit(body);
    }
  }
  return best;
}

/** Whether `prop` (origin/source) is referenced anywhere in the handler scopes. */
export function referencesProp(ctx: AnalysisContext, h: MessageHandler, prop: 'origin' | 'source'): boolean {
  const isTarget = propMatcher(ctx, h, prop);
  let found = false;
  for (const s of [...handlerScopes(ctx, h).map((x) => x.fn), ...h.preFilters]) {
    const visit = (n: ts.Node): void => {
      if (found) return;
      if ((ctx.ts.isPropertyAccessExpression(n) || ctx.ts.isElementAccessExpression(n) || ctx.ts.isIdentifier(n)) && isTarget(n as ts.Expression)) found = true;
      ctx.ts.forEachChild(n, visit);
    };
    const body = (s as { body?: ts.Node }).body;
    if (body) visit(body);
  }
  return found;
}

/** Function-like containing `node` among known handlers, if any. */
export function handlerContaining(ctx: AnalysisContext, handlers: MessageHandler[], node: ts.Node): MessageHandler | undefined {
  for (let p: ts.Node | undefined = node; p; p = p.parent) {
    const h = handlers.find((x) => x.fn === p);
    if (h) return h;
  }
  return undefined;
}
