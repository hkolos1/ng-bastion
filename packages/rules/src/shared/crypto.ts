import type * as ts from 'typescript';
import type { AnalysisContext, CalleeInfo } from '@ngbastion/plugin-api';
import { is, memberName, strip } from './common.js';
import { objectLiteral, objectProp } from './http.js';
import { moduleCall, nodeModules } from './server.js';

export const NODE_CRYPTO = nodeModules('crypto');

/** Compile-time numeric constant: literals (`100_000`, `1e5`), arithmetic, `Math.pow`, `const` / readonly / config-object values. */
export function constantNumber(ctx: AnalysisContext, expr: ts.Expression | undefined, depth = 0): number | undefined {
  const t = ctx.ts;
  if (!expr || depth > 5) return undefined;
  const e = strip(ctx, expr);
  if (t.isNumericLiteral(e)) return Number(e.text.replace(/_/g, ''));
  if (t.isPrefixUnaryExpression(e) && e.operator === t.SyntaxKind.MinusToken) {
    const v = constantNumber(ctx, e.operand, depth + 1);
    return v === undefined ? undefined : -v;
  }
  if (t.isBinaryExpression(e)) {
    const a = constantNumber(ctx, e.left, depth + 1);
    const b = constantNumber(ctx, e.right, depth + 1);
    if (a === undefined || b === undefined) return undefined;
    switch (e.operatorToken.kind) {
      case t.SyntaxKind.AsteriskToken: return a * b;
      case t.SyntaxKind.AsteriskAsteriskToken: return a ** b;
      case t.SyntaxKind.PlusToken: return a + b;
      case t.SyntaxKind.MinusToken: return a - b;
      case t.SyntaxKind.SlashToken: return a / b;
      case t.SyntaxKind.LessThanLessThanToken: return a * 2 ** b;
      default: return undefined;
    }
  }
  if (t.isCallExpression(e) && e.expression.getText() === 'Math.pow' && e.arguments.length === 2) {
    const a = constantNumber(ctx, e.arguments[0], depth + 1);
    const b = constantNumber(ctx, e.arguments[1], depth + 1);
    return a === undefined || b === undefined ? undefined : a ** b;
  }
  if (t.isIdentifier(e) || t.isPropertyAccessExpression(e)) {
    const d = ctx.symbols.declarationOf(e);
    if (!d) return undefined;
    if (t.isVariableDeclaration(d) && d.initializer && t.isVariableDeclarationList(d.parent) && d.parent.flags & t.NodeFlags.Const) return constantNumber(ctx, d.initializer, depth + 1);
    if ((t.isPropertyDeclaration(d) || t.isPropertyAssignment(d) || t.isEnumMember(d)) && d.initializer) return constantNumber(ctx, d.initializer, depth + 1);
  }
  return undefined;
}

/**
 * Whether a byte / string value is a compile-time constant: string constants, `TextEncoder().encode('…')`,
 * `Buffer.from('…')`, literal byte arrays, zero-filled buffers, and `const` / readonly bindings of those.
 */
export function constantBytes(ctx: AnalysisContext, expr: ts.Expression | undefined, depth = 0): boolean {
  const t = ctx.ts;
  if (!expr || depth > 4) return false;
  const e = strip(ctx, expr);
  if (ctx.symbols.constantString(e) !== undefined) return true;
  if (t.isArrayLiteralExpression(e)) return e.elements.length > 0 && e.elements.every((el) => t.isNumericLiteral(strip(ctx, el)));
  const literalBytes = (a: ts.Expression | undefined) => {
    const x = a && strip(ctx, a);
    return !!x && (t.isNumericLiteral(x) || (t.isArrayLiteralExpression(x) && x.elements.every((el) => t.isNumericLiteral(strip(ctx, el)))) || constantBytes(ctx, x, depth + 1));
  };
  if (t.isNewExpression(e) && t.isIdentifier(e.expression) && /^(Uint8Array|ArrayBuffer|Uint16Array|Uint32Array|Int8Array)$/.test(e.expression.text)) {
    return !e.arguments?.length || literalBytes(e.arguments[0]);
  }
  if (t.isCallExpression(e)) {
    const name = memberName(ctx, e.expression);
    if ((name === 'encode' || name === 'from' || name === 'of' || name === 'alloc' || name === 'parse') && e.arguments.length && e.arguments.every((a) => literalBytes(a) || ctx.symbols.constantString(a) !== undefined)) return true;
    return false;
  }
  if (t.isIdentifier(e) || t.isPropertyAccessExpression(e)) {
    let d = ctx.symbols.declarationOf(e);
    if (d && t.isShorthandPropertyAssignment(d)) d = ctx.checker.getShorthandAssignmentValueSymbol(d)?.valueDeclaration;
    if (!d) return false;
    if (t.isVariableDeclaration(d) && d.initializer && t.isVariableDeclarationList(d.parent) && d.parent.flags & t.NodeFlags.Const) return constantBytes(ctx, d.initializer, depth + 1);
    if ((t.isPropertyDeclaration(d) || t.isPropertyAssignment(d)) && d.initializer) return constantBytes(ctx, d.initializer, depth + 1);
  }
  return false;
}

/** `crypto.subtle.<method>()` (browser `SubtleCrypto`, also Node's `webcrypto.subtle`). */
export function subtleCall(ctx: AnalysisContext, call: ts.CallExpression, methods: readonly string[]): CalleeInfo | undefined {
  const info = ctx.symbols.callee(call);
  if (!info || info.declaration || !methods.includes(info.name)) return undefined;
  if (is(info.receiver, ['dom', ...NODE_CRYPTO], 'SubtleCrypto')) return info;
  // Untyped fallback: `crypto.subtle.verify(…)` / `window.crypto.subtle.verify(…)`.
  return /(^|\.)crypto\.subtle$/.test(strip(ctx, call.expression).getText().replace(/\.[\w$]+$/, '')) ? info : undefined;
}

/** Algorithm name of a Web Crypto algorithm argument (`'PBKDF2'` or `{ name: 'PBKDF2', … }`), upper case. */
export function algorithmName(ctx: AnalysisContext, arg: ts.Expression | undefined): string | undefined {
  if (!arg) return undefined;
  const lit = objectLiteral(ctx, arg);
  const n = lit ? objectProp(ctx, lit, 'name') : arg;
  return n ? ctx.symbols.constantString(n)?.toUpperCase() : undefined;
}

/** Node `crypto` function call (`pbkdf2Sync(…)`, `crypto.scrypt(…)`, `require('crypto').verify(…)`). */
export function nodeCryptoCall(ctx: AnalysisContext, call: ts.CallExpression, names: readonly string[]): string | undefined {
  return moduleCall(ctx, call, NODE_CRYPTO, names);
}

/** `CryptoJS.<name>(…)` (global or `crypto-js` import) or a `crypto-js/<name>` default import. */
export function cryptoJsCall(ctx: AnalysisContext, call: ts.CallExpression, name: string): boolean {
  const t = ctx.ts;
  const info = ctx.symbols.callee(call);
  if (info?.declaration) return false;
  const callee = strip(ctx, call.expression);
  if (memberName(ctx, callee) === name && (is(info?.receiver, ['crypto-js']) || (t.isPropertyAccessExpression(callee) && /^CryptoJS$/.test(callee.expression.getText())))) return true;
  return !!info?.origin && info.origin.module === `crypto-js/${name.toLowerCase()}`;
}

/** Hash name normalized to `SHA-1` / `SHA-256` / …: from `'sha256'`, `{ name: 'SHA-256' }`, `CryptoJS.algo.SHA512`. */
export function hashName(ctx: AnalysisContext, e: ts.Expression | undefined): string | undefined {
  if (!e) return undefined;
  const raw = algorithmName(ctx, e) ?? strip(ctx, e).getText().replace(/^.*\./, '');
  const m = /^SHA-?(1|256|384|512)$/i.exec(raw);
  return m ? `SHA-${m[1]}` : undefined;
}

/** A password-hashing / key-derivation call whose parameters are visible. */
export interface KdfCall {
  node: ts.CallExpression;
  kind: 'pbkdf2' | 'scrypt' | 'bcrypt' | 'argon2';
  api: string;
  salt?: ts.Expression;
  iterations?: ts.Expression;
  /** Normalized hash for PBKDF2 when known. */
  hash?: string;
  /** scrypt / argon2 options object. */
  options?: ts.Expression;
  /** bcrypt cost argument (number). */
  cost?: ts.Expression;
}

const BCRYPT = ['bcrypt', 'bcryptjs', 'bcrypt-nodejs'];

/** PBKDF2 (Web Crypto, Node, CryptoJS), scrypt (Node), bcrypt / bcryptjs and argon2 calls. */
export function kdfCalls(ctx: AnalysisContext): KdfCall[] {
  const out: KdfCall[] = [];
  for (const call of ctx.index.calls) {
    const a = call.arguments;
    const subtle = subtleCall(ctx, call, ['deriveBits', 'deriveKey']);
    if (subtle) {
      if (algorithmName(ctx, a[0]) !== 'PBKDF2') continue;
      const alg = objectLiteral(ctx, a[0]);
      out.push({ node: call, kind: 'pbkdf2', api: `crypto.subtle.${subtle.name}(PBKDF2)`, salt: objectProp(ctx, alg, 'salt'), iterations: objectProp(ctx, alg, 'iterations'), hash: hashName(ctx, objectProp(ctx, alg, 'hash')) });
      continue;
    }
    const node = nodeCryptoCall(ctx, call, ['pbkdf2', 'pbkdf2Sync', 'scrypt', 'scryptSync']);
    if (node?.startsWith('pbkdf2')) {
      out.push({ node: call, kind: 'pbkdf2', api: `crypto.${node}()`, salt: a[1], iterations: a[2], hash: hashName(ctx, a[4]) });
      continue;
    }
    if (node) {
      // scrypt(password, salt, keylen[, options][, callback])
      const opts = a[3] && objectLiteral(ctx, a[3]) ? a[3] : undefined;
      out.push({ node: call, kind: 'scrypt', api: `crypto.${node}()`, salt: a[1], ...(opts ? { options: opts } : {}) });
      continue;
    }
    if (cryptoJsCall(ctx, call, 'PBKDF2')) {
      const opts = objectLiteral(ctx, a[2]);
      out.push({ node: call, kind: 'pbkdf2', api: 'CryptoJS.PBKDF2()', salt: a[1], iterations: objectProp(ctx, opts, 'iterations'), hash: hashName(ctx, objectProp(ctx, opts, 'hasher')) });
      continue;
    }
    const bcrypt = moduleCall(ctx, call, BCRYPT, ['hash', 'hashSync', 'genSalt', 'genSaltSync']);
    if (bcrypt) {
      const arg = bcrypt.startsWith('genSalt') ? a[0] : a[1];
      const isCost = arg && constantNumber(ctx, arg) !== undefined;
      out.push({ node: call, kind: 'bcrypt', api: `bcrypt.${bcrypt}()`, ...(isCost ? { cost: arg } : arg && !bcrypt.startsWith('genSalt') ? { salt: arg } : {}) });
      continue;
    }
    const argon = moduleCall(ctx, call, ['argon2'], ['hash']);
    if (argon) {
      const opts = objectLiteral(ctx, a[1]);
      out.push({ node: call, kind: 'argon2', api: 'argon2.hash()', salt: objectProp(ctx, opts, 'salt'), ...(opts ? { options: opts } : {}) });
    }
  }
  return out;
}
