import type * as ts from 'typescript';
import { defineRule, type AnalysisContext, type RuleFinding, type Severity } from '@ngbastion/plugin-api';
import { memberName, receiverOf, strip } from '../shared/common.js';
import { objectLiteral, objectProp } from '../shared/http.js';
import { algorithmName, constantNumber, nodeCryptoCall, subtleCall } from '../shared/crypto.js';

const AEAD = /-(gcm|ccm|ocb)$|^chacha20-poly1305$/i;

function tagSeverity(bits: number): Severity {
  return bits < 96 ? 'medium' : 'low';
}

/** `const d = createDecipheriv(…)` → the variable's declaration, for matching `d.setAuthTag(…)`. */
function declOf(ctx: AnalysisContext, call: ts.Node): ts.Declaration | undefined {
  const t = ctx.ts;
  let n: ts.Node = call;
  while (n.parent && (t.isParenthesizedExpression(n.parent) || t.isAsExpression(n.parent))) n = n.parent;
  return n.parent && t.isVariableDeclaration(n.parent) && n.parent.initializer === n ? n.parent : undefined;
}

export const ngb089 = defineRule({
  meta: {
    id: 'NGB089',
    name: 'Truncated authentication tag',
    category: 'cryptography',
    defaultSeverity: 'medium',
    cwe: ['CWE-326', 'CWE-347'],
    docs: {
      description:
        'Reports authenticated encryption (AES-GCM, AES-CCM, OCB, ChaCha20-Poly1305) configured with an authentication tag shorter than 128 bits: Web Crypto `encrypt` / `decrypt` with `tagLength` < 128, Node `createCipheriv` / `createDecipheriv` with `authTagLength` < 16 bytes, and GCM decryption that accepts a tag of any length (`setAuthTag()` without `authTagLength` and without a visible length check).',
      rationale:
        'The tag is what makes AES-GCM tamper-proof. Its forgery resistance shrinks with its length: a 32-bit tag can be forged after a few billion attempts, and with GCM every successful forgery also reveals information about the authentication key. Node accepts GCM tags from 4 to 16 bytes unless `authTagLength` is fixed, so a decryptor that takes the tag from the message lets an attacker submit a 4-byte tag and brute-force a forgery.',
      patterns: [
        "`crypto.subtle.encrypt/decrypt({ name: 'AES-GCM', tagLength }, …)` with a constant `tagLength` < 128 (< 96: medium severity, 96–120: low)",
        "`createCipheriv` / `createDecipheriv` for `*-gcm`, `*-ccm`, `*-ocb`, `chacha20-poly1305` with `{ authTagLength }` < 16 bytes",
        "`createDecipheriv('aes-…-gcm', key, iv)` without `authTagLength` whose result's `setAuthTag(tag)` is not dominated by a check of the tag's `length`",
      ],
      limitations: [
        'Tag lengths read from configuration at runtime are not assessed.',
        'Length validation in a caller or a helper function is not seen; the decryptor finding is reported with medium confidence.',
        'Libraries other than Web Crypto and Node `crypto` (node-forge, sjcl, libsodium wrappers) are not analyzed.',
      ],
      falsePositives: [
        'Protocols that mandate a short tag (some IoT / constrained formats) are reported; document an exception.',
      ],
      remediation:
        "Use the default 128-bit tag (omit `tagLength`, or pass 128). In Node, pass `{ authTagLength: 16 }` to `createDecipheriv()` for GCM, or reject tags whose `length !== 16` before `setAuthTag()`.",
      example: {
        unsafe: "await crypto.subtle.encrypt({ name: 'AES-GCM', iv, tagLength: 64 }, key, data);",
        safe: "await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, data); // 128-bit tag",
      },
      references: [
        { title: 'NIST SP 800-38D — GCM, Appendix C (tag length)', url: 'https://csrc.nist.gov/pubs/sp/800/38/d/final' },
        { title: 'Node.js — crypto.createDecipheriv authTagLength', url: 'https://nodejs.org/api/crypto.html#cryptocreatedecipherivalgorithm-key-iv-options' },
      ],
    },
  },
  analyze(ctx) {
    const findings: RuleFinding[] = [];
    const deciphers = new Map<ts.Declaration, ts.CallExpression>();
    for (const call of ctx.index.calls) {
      const a = call.arguments;
      const subtle = subtleCall(ctx, call, ['encrypt', 'decrypt']);
      if (subtle) {
        const name = algorithmName(ctx, a[0]);
        if (name !== 'AES-GCM') continue;
        const bits = constantNumber(ctx, objectProp(ctx, objectLiteral(ctx, a[0]), 'tagLength'));
        if (bits !== undefined && bits < 128) {
          findings.push({ node: call, message: `AES-GCM ${subtle.name}() uses a ${bits}-bit authentication tag; forgeries become feasible below 128 bits.`, severity: tagSeverity(bits), confidence: 'high', evidenceKind: 'pattern', evidence: [`tagLength: ${bits}`] });
        }
        continue;
      }
      const fn = nodeCryptoCall(ctx, call, ['createCipheriv', 'createDecipheriv']);
      if (!fn) continue;
      const alg = a[0] && ctx.symbols.constantString(a[0]);
      if (!alg || !AEAD.test(alg)) continue;
      const lenExpr = objectProp(ctx, objectLiteral(ctx, a[3]), 'authTagLength');
      const bytes = constantNumber(ctx, lenExpr);
      if (bytes !== undefined && bytes < 16) {
        findings.push({ node: call, message: `${fn}('${alg}') uses a ${bytes}-byte authentication tag; forgeries become feasible below 16 bytes.`, severity: tagSeverity(bytes * 8), confidence: 'high', evidenceKind: 'pattern', evidence: [`authTagLength: ${bytes}`] });
        continue;
      }
      if (fn === 'createDecipheriv' && !lenExpr && /-gcm$/i.test(alg)) {
        const d = declOf(ctx, call);
        if (d) deciphers.set(d, call);
      }
    }
    if (!deciphers.size) return findings;
    for (const call of ctx.index.calls) {
      if (memberName(ctx, call.expression) !== 'setAuthTag' || !call.arguments[0]) continue;
      const recv = receiverOf(ctx, strip(ctx, call.expression));
      const d = recv && ctx.symbols.declarationOf(strip(ctx, recv));
      const created = d && deciphers.get(d);
      if (!created) continue;
      const tag = strip(ctx, call.arguments[0]);
      const tagText = tag.getText();
      // `if (tag.length !== 16) throw …` (dominating guard). Slicing does not help: `buf.subarray(-16)` of a short message is short.
      const checked = ctx.flow.guards(call).some((g) => g.condition.getText().includes(`${tagText}.length`) || /\b(byteLength|length)\b/.test(g.condition.getText()) && g.condition.getText().includes(tagText));
      if (checked) continue;
      findings.push({
        node: call,
        message: "GCM decipher accepts an authentication tag of any length (4–16 bytes): createDecipheriv() has no authTagLength and the tag's length is not checked, so an attacker can submit a short tag and brute-force a forgery.",
        severity: 'medium',
        confidence: 'medium',
        evidenceKind: 'pattern',
        evidence: [`createDecipheriv at line ${ctx.location(created).line} without authTagLength`, `setAuthTag(${tagText.slice(0, 60)})`],
      });
    }
    return findings;
  },
});
