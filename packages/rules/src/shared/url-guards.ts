import type * as ts from 'typescript';
import type { AnalysisContext } from '@ngbastion/plugin-api';
import { memberName, receiverOf, strip } from './common.js';

/**
 * Classification of the conditions that must hold before a URL reaches a sink.
 * - host: `strong` (same-origin / allowlist / safe relative path), `weak` (substring or
 *   prefix checks that can be bypassed), `custom` (unknown project validator).
 * - scheme: `strong` (protocol allowlist / fixed scheme / relative path), `custom`.
 */
export interface UrlValidation {
  host?: 'strong' | 'weak' | 'custom';
  scheme?: 'strong' | 'custom';
  evidence: string[];
}

interface Fact {
  expr: ts.Expression;
  holds: boolean;
}

const RANK = { weak: 1, custom: 2, strong: 3 } as const;

/** Atomic facts known to be true/false when the guarded code runs. */
function facts(ctx: AnalysisContext, cond: ts.Expression, holds: boolean, depth = 0): Fact[] {
  const t = ctx.ts;
  const e = strip(ctx, cond);
  if (depth > 4) return [{ expr: e, holds }];
  if (t.isPrefixUnaryExpression(e) && e.operator === t.SyntaxKind.ExclamationToken) return facts(ctx, e.operand, !holds, depth + 1);
  if (t.isBinaryExpression(e)) {
    const k = e.operatorToken.kind;
    if ((k === t.SyntaxKind.AmpersandAmpersandToken && holds) || (k === t.SyntaxKind.BarBarToken && !holds)) {
      return [...facts(ctx, e.left, holds, depth + 1), ...facts(ctx, e.right, holds, depth + 1)];
    }
  }
  // `const isApi = req.url.startsWith(API); if (isApi) …`
  if (t.isIdentifier(e)) {
    const d = ctx.symbols.declarationOf(e);
    if (d && t.isVariableDeclaration(d) && d.initializer && t.isVariableDeclarationList(d.parent) && d.parent.flags & t.NodeFlags.Const) {
      return facts(ctx, d.initializer, holds, depth + 1);
    }
  }
  return [{ expr: e, holds }];
}

function identifiers(ctx: AnalysisContext, node: ts.Node, out = new Set<string>()): Set<string> {
  const t = ctx.ts;
  if (t.isIdentifier(node)) out.add(node.text);
  t.forEachChild(node, (c) => void identifiers(ctx, c, out));
  return out;
}

const text = (n: ts.Node) => n.getText().replace(/\s+/g, '');
const mentions = (n: ts.Node, re: RegExp) => re.test(text(n));

/** Absolute origin with a path separator: `https://host/` (prefix-safe). */
const FIXED_ORIGIN = /^https?:\/\/[^/?#\s\\]+[/?#]/i;

/** Classifies a single fact about a URL. Returns the kinds of validation it provides. */
function classify(ctx: AnalysisContext, f: Fact): { host?: 'strong' | 'weak' | 'custom'; scheme?: 'strong' | 'custom'; relativeOnly?: boolean; noProtocolRelative?: boolean; why: string } | undefined {
  const t = ctx.ts;
  const e = f.expr;
  const src = e.getText().replace(/\s+/g, ' ').slice(0, 80);
  if (t.isBinaryExpression(e)) {
    const k = e.operatorToken.kind;
    const eq = k === t.SyntaxKind.EqualsEqualsEqualsToken || k === t.SyntaxKind.EqualsEqualsToken;
    const ne = k === t.SyntaxKind.ExclamationEqualsEqualsToken || k === t.SyntaxKind.ExclamationEqualsToken;
    if ((eq && f.holds) || (ne && !f.holds)) {
      if (mentions(e, /\.origin\b/)) return { host: 'strong', scheme: 'strong', why: `same-origin comparison \`${src}\`` };
      if (mentions(e, /\.(hostname|host)\b/)) return { host: 'strong', why: `host comparison \`${src}\`` };
      if (mentions(e, /\.protocol\b/)) return { scheme: 'strong', why: `protocol comparison \`${src}\`` };
    }
    if ((k === t.SyntaxKind.ExclamationEqualsEqualsToken || k === t.SyntaxKind.GreaterThanToken || k === t.SyntaxKind.GreaterThanEqualsToken) && f.holds && mentions(e, /\.indexOf\(/)) {
      return { host: 'weak', why: `substring check \`${src}\`` };
    }
    return undefined;
  }
  if (!t.isCallExpression(e) || (!f.holds && !isStartsWith(ctx, e))) return undefined;
  const callee = strip(ctx, e.expression);
  const name = memberName(ctx, callee) ?? (t.isIdentifier(callee) ? callee.text : undefined);
  const arg0 = e.arguments[0];
  const recv = receiverOf(ctx, callee);

  if ((name === 'startsWith') && arg0) {
    const c = ctx.symbols.constantString(arg0);
    if (c === undefined) {
      // startsWith(environment.apiUrl) — configured origin.
      const argText = text(arg0);
      if (f.holds && /(api|base|backend|origin|server|host)\w*(url|uri|origin)?$/i.test(argText)) return { host: 'strong', scheme: 'strong', why: `prefix check against configured origin \`${src}\`` };
      return f.holds ? { host: 'weak', why: `prefix check \`${src}\`` } : undefined;
    }
    if (!f.holds) return (c === '//' || c === '/\\') ? { noProtocolRelative: true, why: `excludes protocol-relative URLs \`${src}\`` } : undefined;
    if (c === '/') return { relativeOnly: true, scheme: 'strong', why: `relative-path check \`${src}\`` };
    if (c.startsWith('/') && c.length > 1 && c[1] !== '/' && c[1] !== '\\') return { host: 'strong', scheme: 'strong', why: `internal path prefix \`${src}\`` };
    if (FIXED_ORIGIN.test(c)) return { host: 'strong', scheme: 'strong', why: `fixed origin prefix \`${src}\`` };
    if (/^https?:/i.test(c)) return { host: 'weak', scheme: 'strong', why: `scheme prefix check \`${src}\`` };
    return { host: 'weak', why: `prefix check \`${src}\`` };
  }
  if (!f.holds) return undefined;
  if ((name === 'includes' || name === 'has') && arg0 && recv) {
    const recvConst = ctx.symbols.constantString(recv);
    if (recvConst !== undefined || t.isStringLiteralLike(strip(ctx, recv))) return undefined;
    if (mentions(arg0, /\.protocol\b/)) return { scheme: 'strong', why: `protocol allowlist \`${src}\`` };
    if (mentions(arg0, /\.origin\b/)) return { host: 'strong', scheme: 'strong', why: `origin allowlist \`${src}\`` };
    if (mentions(arg0, /\.(hostname|host)\b/)) return { host: 'strong', why: `host allowlist \`${src}\`` };
    // `url.includes('example.com')` — substring of the URL itself.
    return { host: 'weak', why: `substring check \`${src}\`` };
  }
  if ((name === 'some' || name === 'every') && arg0) {
    if (/startsWith|===|\.origin|\.host/.test(text(arg0))) return { host: 'strong', scheme: 'strong', why: `allowlist check \`${src}\`` };
  }
  if (name === 'endsWith' || name === 'match' || name === 'search' || name === 'indexOf') return { host: 'weak', why: `weak string check \`${src}\`` };
  if (name === 'test' && recv && t.isRegularExpressionLiteral(strip(ctx, recv))) {
    const re = (strip(ctx, recv) as ts.RegularExpressionLiteral).text;
    if (/^\/\^\\\/(\(\?!\\\/\)|\[\^\\\/)/.test(re)) return { host: 'strong', scheme: 'strong', why: `relative-path pattern ${re}` };
    if (/^\/\^https\?:\\\/\\\/[\w\\.-]+(\\\/|\(\\\/|\$)/i.test(re) && !/^\/\^https\?:\\\/\\\/\[/.test(re)) return { host: 'strong', scheme: 'strong', why: `anchored origin pattern ${re}` };
    if (/^\/\^\(?https/i.test(re)) return { scheme: 'strong', host: 'weak', why: `scheme pattern ${re}` };
    return { host: 'weak', why: `unanchored pattern ${re}` };
  }
  const info = ctx.symbols.callee(e);
  if (info?.declaration) return { host: 'custom', scheme: 'custom', why: `custom validator ${info.name}() is not analyzed` };
  return undefined;
}

function isStartsWith(ctx: AnalysisContext, e: ts.CallExpression): boolean {
  return memberName(ctx, e.expression) === 'startsWith';
}

/**
 * Validation guarding `sink`, considering only conditions that mention one of `names`
 * (the traced value's identifiers). Pass `names = undefined` to accept every condition.
 */
export function urlValidation(ctx: AnalysisContext, sink: ts.Node, names: ReadonlySet<string> | undefined): UrlValidation {
  const out: UrlValidation = { evidence: [] };
  let relative = false;
  let noProtocolRelative = false;
  const bump = <K extends 'host' | 'scheme'>(k: K, v: NonNullable<UrlValidation[K]>) => {
    const cur = out[k];
    if (!cur || RANK[v] > RANK[cur]) out[k] = v;
  };
  for (const g of ctx.flow.guards(sink)) {
    for (const f of facts(ctx, g.condition, g.whenTrue)) {
      if (names && ![...identifiers(ctx, f.expr)].some((n) => names.has(n))) continue;
      const c = classify(ctx, f);
      if (!c) continue;
      out.evidence.push(c.why);
      if (c.host) bump('host', c.host);
      if (c.scheme) bump('scheme', c.scheme);
      relative ||= !!c.relativeOnly;
      noProtocolRelative ||= !!c.noProtocolRelative;
    }
  }
  if (relative) bump('host', noProtocolRelative ? 'strong' : 'weak');
  return out;
}

/** Identifiers of a value expression plus names traversed by its trace. */
export function valueNames(ctx: AnalysisContext, value: ts.Expression, traced: readonly string[]): Set<string> {
  return new Set([...identifiers(ctx, value), ...traced]);
}
