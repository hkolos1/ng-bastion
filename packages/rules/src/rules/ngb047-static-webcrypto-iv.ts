import type * as ts from 'typescript';
import { defineRule, type AnalysisContext, type RuleFinding, type Severity } from '@ngbastion/plugin-api';
import { is, strip } from '../shared/common.js';
import { objectLiteral, objectProp } from '../shared/http.js';

const MODES: Record<string, { param: string; severity: Severity; why: string }> = {
  'aes-gcm': { param: 'iv', severity: 'high', why: 'reusing a nonce with the same key reveals the XOR of the plaintexts and lets an attacker forge authentication tags' },
  'aes-ctr': { param: 'counter', severity: 'high', why: 'reusing a counter block with the same key reveals the XOR of the plaintexts' },
  'aes-cbc': { param: 'iv', severity: 'medium', why: 'a fixed IV makes encryption deterministic, so equal plaintext prefixes produce equal ciphertext' },
};

type IvKind = 'constant' | 'reused';

/** Whether the IV expression is a literal / fixed buffer, or a long-lived variable that is not regenerated per call. */
function ivKind(ctx: AnalysisContext, e: ts.Expression, fn: ts.Node | undefined, depth = 0): IvKind | undefined {
  const t = ctx.ts;
  const x = strip(ctx, e);
  if (ctx.symbols.constantString(x) !== undefined) return 'constant';
  if (t.isNewExpression(x) && t.isIdentifier(x.expression) && /^(Uint8Array|ArrayBuffer|Uint32Array|DataView)$/.test(x.expression.text)) {
    const a = x.arguments?.[0];
    if (!a || t.isNumericLiteral(strip(ctx, a))) return 'constant'; // zero-filled
    if (t.isArrayLiteralExpression(strip(ctx, a)) && (strip(ctx, a) as ts.ArrayLiteralExpression).elements.every((el) => t.isNumericLiteral(strip(ctx, el)))) return 'constant';
    return a && depth < 3 ? ivKind(ctx, a, fn, depth + 1) : undefined;
  }
  if (t.isCallExpression(x)) {
    const name = t.isPropertyAccessExpression(x.expression) ? x.expression.name.text : t.isIdentifier(x.expression) ? x.expression.text : '';
    if (name === 'getRandomValues' || name === 'randomBytes' || name === 'randomFillSync') return undefined;
    if ((name === 'encode' || name === 'from' || name === 'of') && x.arguments.length && x.arguments.every((a) => ctx.symbols.constantString(a) !== undefined || t.isNumericLiteral(strip(ctx, a)) || t.isArrayLiteralExpression(strip(ctx, a)))) return 'constant';
    return undefined;
  }
  if (t.isIdentifier(x) || t.isPropertyAccessExpression(x)) {
    let d = ctx.symbols.declarationOf(x);
    // `{ name, iv }`: the shorthand property resolves to the property, not to the variable it reads.
    if (d && t.isShorthandPropertyAssignment(d)) d = ctx.checker.getShorthandAssignmentValueSymbol(d)?.valueDeclaration;
    if (!d) return undefined;
    const inside = !!fn && d.pos >= fn.pos && d.end <= fn.end;
    if ((t.isVariableDeclaration(d) || t.isPropertyDeclaration(d)) && d.initializer) {
      const k = depth < 3 ? ivKind(ctx, d.initializer, fn, depth + 1) : undefined;
      if (k === 'constant') return 'constant';
      if (!inside && t.isVariableDeclaration(d) && /getRandomValues|randomBytes/.test(d.initializer.getText())) return 'reused';
      if (!inside && t.isPropertyDeclaration(d) && /getRandomValues|randomBytes/.test(d.initializer.getText())) return 'reused';
    }
  }
  return undefined;
}

export const ngb047 = defineRule({
  meta: {
    id: 'NGB047',
    name: 'Static IV in Web Crypto encryption',
    category: 'cryptography',
    defaultSeverity: 'high',
    cwe: ['CWE-329', 'CWE-323'],
    docs: {
      description:
        "Reports `crypto.subtle.encrypt()` with AES-GCM, AES-CTR or AES-CBC whose `iv` / `counter` is a constant (string, `TextEncoder().encode('…')`, literal byte array, zero-filled `new Uint8Array(12)`) or a random value created once at module / class level and reused for every call.",
      rationale:
        "AES-GCM and AES-CTR are only secure when every encryption under a key uses a fresh IV/counter: one repetition reveals the XOR of two plaintexts and, for GCM, lets an attacker forge authenticated messages. AES-CBC with a fixed IV leaks which messages share a prefix. Static IVs are a common copy-paste mistake in client-side \"encrypted storage\" helpers.",
      patterns: [
        "`crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, data)` on the DOM `SubtleCrypto` (algorithm object inline or in a `const`)",
        "Constant IVs: string / template constants, `new TextEncoder().encode('…')`, `Uint8Array.from([...])`, `new Uint8Array([1, 2, …])`, `new Uint8Array(12)` (all zeros)",
        'Reused IVs: `const IV = crypto.getRandomValues(new Uint8Array(12))` at module level or as a class field, used inside the encrypting function',
        'AES-GCM / AES-CTR: high severity; AES-CBC: medium',
      ],
      limitations: [
        'IVs derived deterministically from data (counters, hashes of the plaintext) are not recognized as reused.',
        'Encryption through libraries (crypto-js, node-forge, libsodium wrappers) is not analyzed.',
      ],
      falsePositives: [
        'A key that is itself used only once (fresh random key per message) makes a fixed IV harmless; such designs are rare and are still reported.',
      ],
      remediation:
        "Generate a fresh IV for every encryption (`crypto.getRandomValues(new Uint8Array(12))` for AES-GCM), and store or send it next to the ciphertext; it does not need to be secret.",
      example: {
        unsafe: `const IV = new TextEncoder().encode('0123456789ab');
await crypto.subtle.encrypt({ name: 'AES-GCM', iv: IV }, key, data);`,
        safe: `const iv = crypto.getRandomValues(new Uint8Array(12));
const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, data);
return { iv, ciphertext };`,
      },
      references: [
        { title: 'MDN — SubtleCrypto.encrypt() (AES-GCM iv)', url: 'https://developer.mozilla.org/docs/Web/API/AesGcmParams' },
        { title: 'NIST SP 800-38D — GCM IV uniqueness requirement', url: 'https://csrc.nist.gov/pubs/sp/800/38/d/final' },
      ],
    },
  },
  analyze(ctx) {
    const findings: RuleFinding[] = [];
    for (const call of ctx.index.calls) {
      const info = ctx.symbols.callee(call);
      if (!info || info.declaration || info.name !== 'encrypt' || !is(info.receiver, 'dom', 'SubtleCrypto') || !call.arguments[0]) continue;
      const alg = objectLiteral(ctx, call.arguments[0]);
      const algKey = (ctx.symbols.constantString(objectProp(ctx, alg, 'name') ?? call.arguments[0]) ?? '').toLowerCase();
      const mode = Object.hasOwn(MODES, algKey) ? MODES[algKey] : undefined;
      if (!alg || !mode) continue;
      const iv = objectProp(ctx, alg, mode.param);
      if (!iv) continue;
      const kind = ivKind(ctx, iv, ctx.flow.enclosingFunction(call));
      if (!kind) continue;
      const algName = ctx.symbols.constantString(objectProp(ctx, alg, 'name')!)!;
      findings.push({
        node: call,
        message: `${algName} encryption uses a ${kind === 'constant' ? 'constant' : 'reused (created once, outside this function)'} ${mode.param}; ${mode.why}.`,
        confidence: kind === 'constant' ? 'high' : 'medium',
        severity: mode.severity,
        evidenceKind: 'pattern',
        evidence: [`${mode.param}: ${iv.getText().slice(0, 80)}`],
      });
    }
    return findings;
  },
});
