import type * as ts from 'typescript';
import type { AnalysisContext, Confidence, TaintResult } from '@ngbastion/plugin-api';
import { is, memberName, receiverOf, strip } from './common.js';
import { classifyName, describeEvidence, isRedacted, sensitivityOf, words, type SensitiveCategory, type SensitivityEvidence } from './sensitivity.js';

export interface StorageWrite {
  node: ts.Node;
  /** Human label: `localStorage`, `sessionStorage`, `Web Storage`, `IndexedDB`, `document.cookie`. */
  store: string;
  persistent: boolean;
  /** Constant key (storage key, IndexedDB key argument or cookie name). */
  key?: string;
  value: ts.Expression;
}

function storageLabel(ctx: AnalysisContext, recv: ts.Expression): { store: string; persistent: boolean } {
  const text = strip(ctx, recv).getText();
  if (/sessionStorage$/.test(text)) return { store: 'sessionStorage', persistent: false };
  if (/localStorage$/.test(text)) return { store: 'localStorage', persistent: true };
  return { store: 'Web Storage', persistent: true };
}

/** Browser storage writes: Web Storage setItem / property writes, IndexedDB put/add and (optionally) cookie writes. */
export function storageWrites(ctx: AnalysisContext, opts: { cookies: boolean }): StorageWrite[] {
  const t = ctx.ts;
  const out: StorageWrite[] = [];
  const isStorage = (e: ts.Expression | undefined) => !!e && is(ctx.symbols.typeOrigin(e), 'dom', 'Storage');
  for (const call of ctx.index.calls) {
    const callee = strip(ctx, call.expression);
    const name = memberName(ctx, callee);
    const recv = receiverOf(ctx, callee);
    if (name === 'setItem' && isStorage(recv) && call.arguments[1]) {
      const key = ctx.symbols.constantString(call.arguments[0]!);
      out.push({ node: call, ...storageLabel(ctx, recv!), ...(key !== undefined ? { key } : {}), value: call.arguments[1] });
    } else if ((name === 'put' || name === 'add') && recv && is(ctx.symbols.typeOrigin(recv), 'dom', 'IDBObjectStore') && call.arguments[0]) {
      const key = call.arguments[1] ? ctx.symbols.constantString(call.arguments[1]) : undefined;
      out.push({ node: call, store: 'IndexedDB', persistent: true, ...(key !== undefined ? { key } : {}), value: call.arguments[0] });
    }
  }
  for (const a of ctx.index.assignments) {
    const left = strip(ctx, a.left);
    const recv = receiverOf(ctx, left);
    if (isStorage(recv)) {
      const key = memberName(ctx, left) ?? (t.isElementAccessExpression(left) ? ctx.symbols.constantString(left.argumentExpression) : undefined);
      out.push({ node: a, ...storageLabel(ctx, recv!), ...(key !== undefined ? { key } : {}), value: a.right });
    } else if (opts.cookies && memberName(ctx, left) === 'cookie' && recv && is(ctx.symbols.typeOrigin(recv), 'dom', 'Document')) {
      const prefix = cookieName(ctx, a.right);
      out.push({ node: a, store: 'document.cookie', persistent: true, ...(prefix ? { key: prefix } : {}), value: a.right });
    }
  }
  return out;
}

function cookieName(ctx: AnalysisContext, e: ts.Expression): string | undefined {
  const t = ctx.ts;
  const x = strip(ctx, e);
  const head = t.isTemplateExpression(x) ? x.head.text : t.isBinaryExpression(x) ? ctx.symbols.constantString(x.left) : ctx.symbols.constantString(x);
  const m = head && /^\s*([^=;\s]+)\s*=/.exec(head);
  return m?.[1];
}

/** Qualifiers that mark a payment/credential name as masked or opaque, e.g. `maskedPan`, `hashedPassword`. */
const NEUTRALIZING = new Set(['masked', 'redacted', 'hashed', 'hash', 'last4', 'truncated', 'tokenized', 'encrypted', 'obfuscated']);

function neutralized(term: string): boolean {
  return words(term).some((w) => NEUTRALIZING.has(w));
}

export interface StorageAssessment {
  confidence: Confidence;
  evidence: string[];
  strong: boolean;
  /** Evidence came from the key, the value, or both. */
  keyEvidence: boolean;
  valueEvidence: boolean;
}

/** Card expiry is metadata for classifyName but part of cardholder data when stored next to a card. */
function extraPayment(term: string): SensitivityEvidence['match'] | undefined {
  const w = words(term);
  if (w.includes('card') && w.some((x) => x === 'expiry' || x === 'expiration' || x === 'exp')) return { category: 'payment', term, strength: 'weak' };
  return undefined;
}

/**
 * Scores evidence that a storage write persists `category` data.
 * Confidence: high when the key and the value agree or a strong direct name/literal exists;
 * medium for a single direct indicator; low when only data-flow names suggest it.
 */
export function assessWrite(ctx: AnalysisContext, w: StorageWrite, category: SensitiveCategory): StorageAssessment | undefined {
  const trace: TaintResult = ctx.taint.trace(w.value, { context: 'generic' });
  if (isRedacted(ctx, w.value, trace)) return undefined;
  const keyMatch = w.key !== undefined ? (classifyName(w.key) ?? (category === 'payment' ? extraPayment(w.key) : undefined)) : undefined;
  const keyEv = keyMatch && keyMatch.category === category && !neutralized(w.key!) ? keyMatch : undefined;
  const valueEvs = sensitivityOf(ctx, w.value, trace).filter((e) => e.match.category === category && !neutralized(e.match.term));
  if (category === 'payment') {
    for (const n of trace.names) {
      const m = extraPayment(n);
      if (m) valueEvs.push({ match: m, via: 'origin' });
    }
  }
  const direct = valueEvs.filter((e) => e.via === 'name' || e.via === 'literal');
  if (!keyEv && !valueEvs.length) return undefined;
  const strong = (keyEv?.strength === 'strong') || direct.some((e) => e.match.strength === 'strong');
  let confidence: Confidence;
  if ((keyEv && direct.length) || strong) confidence = 'high';
  else if (keyEv || direct.length || valueEvs.some((e) => e.match.strength === 'strong')) confidence = 'medium';
  else confidence = 'low';
  return {
    confidence,
    strong,
    keyEvidence: !!keyEv,
    valueEvidence: valueEvs.length > 0,
    evidence: [
      ...(keyEv ? [`storage key '${w.key}' (${keyEv.category}, ${keyEv.strength})`] : []),
      ...valueEvs.slice(0, 4).map(describeEvidence),
    ],
  };
}
