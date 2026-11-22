import type * as ts from 'typescript';
import type { AnalysisContext, TaintResult } from '@ngbastion/plugin-api';

export type SensitiveCategory = 'credential' | 'payment';

export interface SensitiveMatch {
  category: SensitiveCategory;
  /** The identifier, property or key that matched. */
  term: string;
  /** `strong`: unambiguous noun (cvv, password, accessToken). `weak`: generic (token, secret on its own). */
  strength: 'strong' | 'weak';
}

/** Splits `accessToken`, `ACCESS_TOKEN`, `access-token`, `x.access_token` into lowercase words. */
export function words(name: string): string[] {
  return name
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .replace(/([A-Z]+)([A-Z][a-z])/g, '$1 $2')
    .split(/[^A-Za-z0-9]+/)
    .filter(Boolean)
    .map((w) => w.toLowerCase());
}

const CREDENTIAL_HEADS = new Set(['password', 'passwd', 'pwd', 'passphrase', 'secret', 'token', 'jwt', 'credential', 'credentials', 'apikey', 'sessionid', 'bearer', 'authorization', 'otp', 'totp', 'mfa']);
const STRONG_TOKEN_QUALIFIERS = new Set(['access', 'refresh', 'id', 'auth', 'session', 'bearer', 'api', 'oauth', 'jwt', 'identity']);
const NON_SECRET_TOKEN_QUALIFIERS = new Set(['csrf', 'xsrf', 'payment', 'card', 'push', 'fcm', 'device', 'notification', 'next', 'page', 'continuation', 'cursor', 'cancel', 'cancellation', 'injection', 'lexer', 'parse', 'design', 'theme', 'color', 'spacing']);
const KEY_QUALIFIERS = new Set(['api', 'private', 'secret', 'signing', 'access', 'encryption', 'client']);
const PAYMENT_HEADS = new Set(['pan', 'cvv', 'cvc', 'cvv2', 'cvc2', 'csc', 'ccnum', 'ccnumber', 'cardnumber', 'cardnum', 'track1', 'track2', 'trackdata']);
/** Words that turn a sensitive noun into metadata when they are the head (last word). */
const METADATA_HEADS = new Set([
  'expiry', 'expires', 'expiration', 'exp', 'type', 'name', 'key', 'url', 'uri', 'endpoint', 'header', 'length', 'count', 'ttl',
  'timeout', 'masked', 'redacted', 'hash', 'hashed', 'last4', 'four', 'hint', 'placeholder', 'label', 'field', 'regex', 'pattern',
  'valid', 'invalid', 'required', 'error', 'errors', 'min', 'max', 'policy', 'strength', 'visible', 'shown', 'brand', 'id', 'ref',
  'reference', 'fingerprint', 'status', 'state', 'changed', 'enabled', 'mode', 'format', 'mask', 'bin', 'holder', 'present', 'exists',
  'loading', 'service', 'interceptor', 'provider', 'store', 'storage', 'manager', 'helper', 'util', 'utils', 'form', 'control', 'input',
  'request', 'dialog', 'component', 'module', 'path', 'route', 'prefix', 'suffix', 'scheme', 'claims', 'payload', 'subject', 'issuer',
]);
const BOOLEAN_PREFIXES = new Set(['is', 'has', 'show', 'hide', 'can', 'should', 'needs', 'toggle', 'with', 'use', 'on', 'handle', 'get', 'set', 'remove', 'clear', 'validate', 'forgot']);

/** Classifies an identifier / property / storage key by its head noun. */
export function classifyName(name: string): SensitiveMatch | undefined {
  const w = words(name);
  if (!w.length) return undefined;
  const head = w[w.length - 1]!;
  const prev = w[w.length - 2];
  // `showPassword`, `isTokenExpired`, `getToken` describe behaviour, not values.
  if (BOOLEAN_PREFIXES.has(w[0]!) && w.length > 1) return undefined;
  const joined = w.join('');
  if (PAYMENT_HEADS.has(head) || PAYMENT_HEADS.has(joined)) return { category: 'payment', term: name, strength: 'strong' };
  if ((head === 'number' || head === 'num' || head === 'no') && (prev === 'card' || prev === 'cc' || prev === 'credit' || prev === 'pan')) {
    return { category: 'payment', term: name, strength: 'strong' };
  }
  if (head === 'code' && (prev === 'security' || prev === 'verification') && w.includes('card')) return { category: 'payment', term: name, strength: 'strong' };
  if (head === 'code' && prev === 'security') return { category: 'payment', term: name, strength: 'weak' };
  if (METADATA_HEADS.has(head) && !(head === 'key' && prev && KEY_QUALIFIERS.has(prev)) && !(head === 'id' && prev === 'session')) return undefined;
  if (head === 'key' && prev && KEY_QUALIFIERS.has(prev)) return { category: 'credential', term: name, strength: 'strong' };
  if (head === 'id' && prev === 'session') return { category: 'credential', term: name, strength: 'strong' };
  if (head === 'token' && prev && NON_SECRET_TOKEN_QUALIFIERS.has(prev)) return undefined;
  if (head === 'token') return { category: 'credential', term: name, strength: prev && STRONG_TOKEN_QUALIFIERS.has(prev) ? 'strong' : 'weak' };
  if (CREDENTIAL_HEADS.has(head) || CREDENTIAL_HEADS.has(joined)) {
    const strong = head !== 'secret' && head !== 'credential' && head !== 'credentials';
    return { category: 'credential', term: name, strength: strong ? 'strong' : 'weak' };
  }
  if (joined === 'accesstoken' || joined === 'refreshtoken' || joined === 'idtoken') return { category: 'credential', term: name, strength: 'strong' };
  return undefined;
}

/** Luhn-valid 13–19 digit strings (separators allowed). Only synthetic test numbers belong in fixtures. */
export function looksLikePan(value: string): boolean {
  const digits = value.replace(/[\s-]/g, '');
  if (!/^\d{13,19}$/.test(digits) || /^(\d)\1+$/.test(digits)) return false;
  let sum = 0;
  for (let i = 0; i < digits.length; i++) {
    let d = Number(digits[digits.length - 1 - i]);
    if (i % 2 === 1) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
  }
  return sum % 10 === 0;
}

const REDACTION = /mask|redact|obfusc|truncat|hash|sha\d|digest|last4|lastfour|anonymi[sz]|scrub|censor|encrypt/i;

/** True when the expression visibly passes through a redaction step. */
export function isRedacted(ctx: AnalysisContext, expr: ts.Expression, trace?: TaintResult): boolean {
  const { ts: t } = ctx;
  let found = false;
  const visit = (n: ts.Node): void => {
    if (found) return;
    if (t.isCallExpression(n)) {
      const callee = n.expression;
      const name = t.isIdentifier(callee) ? callee.text : t.isPropertyAccessExpression(callee) ? callee.name.text : '';
      if (REDACTION.test(name)) found = true;
      // `.slice(-4)` / `.substring(x.length - 4)` keep only a suffix.
      if ((name === 'slice' || name === 'substr') && n.arguments[0] && t.isPrefixUnaryExpression(n.arguments[0])) found = true;
      // `.replace(/\d(?=\d{4})/g, '*')` style masking.
      if ((name === 'replace' || name === 'replaceAll') && n.arguments[1] && t.isStringLiteralLike(n.arguments[1]) && /^[*•x#]+$/i.test(n.arguments[1].text)) found = true;
    }
    t.forEachChild(n, visit);
  };
  visit(expr);
  if (!found && trace) found = trace.names.some((n) => REDACTION.test(n));
  return found;
}

export interface SensitivityEvidence {
  match: SensitiveMatch;
  /** `name`: the value itself is named like a secret. `origin`: a name along the data flow. `type`: a property of its type. `literal`: the literal value. */
  via: 'name' | 'origin' | 'type' | 'literal' | 'key';
}

/** Names that directly label the value (`this.auth.accessToken` → accessToken; `{ cvv: x }` → cvv). */
export function directNames(ctx: AnalysisContext, expr: ts.Expression, depth = 0): string[] {
  const t = ctx.ts;
  let e: ts.Expression = expr;
  while (t.isParenthesizedExpression(e) || t.isAsExpression(e) || t.isNonNullExpression(e) || t.isAwaitExpression(e)) e = e.expression;
  if (t.isIdentifier(e)) return [e.text];
  if (t.isPropertyAccessExpression(e)) return [e.name.text];
  if (t.isElementAccessExpression(e) && t.isStringLiteralLike(e.argumentExpression)) return [e.argumentExpression.text];
  if (depth > 3) return [];
  if (t.isObjectLiteralExpression(e)) {
    return e.properties.flatMap((p) => {
      const key = p.name && (t.isIdentifier(p.name) || t.isStringLiteral(p.name)) ? p.name.text : undefined;
      const inner = t.isPropertyAssignment(p) ? directNames(ctx, p.initializer, depth + 1) : t.isSpreadAssignment(p) ? directNames(ctx, p.expression, depth + 1) : [];
      return [...(key ? [key] : []), ...inner];
    });
  }
  if (t.isCallExpression(e)) {
    const callee = e.expression;
    // JSON.stringify(x), String(x): look through.
    const name = t.isIdentifier(callee) ? callee.text : t.isPropertyAccessExpression(callee) ? callee.name.text : '';
    if (['stringify', 'String', 'toString', 'trim'].includes(name)) {
      const target = e.arguments[0] ?? (t.isPropertyAccessExpression(callee) ? callee.expression : undefined);
      return target ? directNames(ctx, target, depth + 1) : [];
    }
  }
  if (t.isTemplateExpression(e)) return e.templateSpans.flatMap((s) => directNames(ctx, s.expression, depth + 1));
  if (t.isBinaryExpression(e)) return [...directNames(ctx, e.left, depth + 1), ...directNames(ctx, e.right, depth + 1)];
  if (t.isArrayLiteralExpression(e)) return e.elements.flatMap((x) => directNames(ctx, x, depth + 1));
  return [];
}

/**
 * Collects evidence that `expr` carries credentials or payment data. Ordered by strength:
 * direct names, the value's declared type properties, names along the traced flow, literal PANs.
 */
export function sensitivityOf(ctx: AnalysisContext, expr: ts.Expression, trace?: TaintResult): SensitivityEvidence[] {
  const out: SensitivityEvidence[] = [];
  const seen = new Set<string>();
  const add = (name: string, via: SensitivityEvidence['via']) => {
    const m = classifyName(name);
    if (m && !seen.has(`${m.category}:${name}`)) {
      seen.add(`${m.category}:${name}`);
      out.push({ match: m, via });
    }
  };
  for (const n of directNames(ctx, expr)) add(n, 'name');
  const t = ctx.ts;
  let inner: ts.Expression = expr;
  while (t.isCallExpression(inner) && inner.arguments[0] && /stringify/.test(inner.expression.getText())) inner = inner.arguments[0];
  if (!t.isStringLiteralLike(inner)) {
    for (const p of ctx.symbols.propertyNames(inner)) add(p, 'type');
  }
  for (const n of trace?.names ?? []) add(n, 'origin');
  for (const c of trace?.constants ?? []) {
    if (looksLikePan(c)) out.push({ match: { category: 'payment', term: 'card-number literal', strength: 'strong' }, via: 'literal' });
  }
  if (t.isStringLiteralLike(expr) && looksLikePan(expr.text)) out.push({ match: { category: 'payment', term: 'card-number literal', strength: 'strong' }, via: 'literal' });
  return out;
}

export function describeEvidence(e: SensitivityEvidence): string {
  const how = { name: 'value is named', origin: 'data flow passes through', type: 'value type has property', literal: 'literal looks like', key: 'storage key' }[e.via];
  return `${how} '${e.match.term}' (${e.match.category}, ${e.match.strength})`;
}
