import type * as ts from 'typescript';
import { defineRule, type RuleFinding, type Severity } from '@ngbastion/plugin-api';
import { memberName, strip } from '../shared/common.js';
import { objectLiteral, objectProp } from '../shared/http.js';
import { algorithmName, constantNumber, nodeCryptoCall, subtleCall } from '../shared/crypto.js';

const RSA_MIN = 2048;
const DH_MIN = 2048;
/** Named curves with less than 112-bit security (fewer than 224 bits). */
const WEAK_CURVE = /^(secp(112|128|160|192)[rk]\d|prime192v\d|p-?192|brainpoolp(160|192)[rt]1|sect(113|131|163|193)[rk]\d|c2(pnb|tnb)\d+\w*|wap-wsg-idm-ecid-wtls\d+)$/i;

function sizeIssue(bits: number, min: number, what: string): { severity: Severity; message: string } | undefined {
  if (bits >= min) return undefined;
  return { severity: bits <= 1024 ? 'high' : 'medium', message: `${what} of ${bits} bits is below the ${min}-bit minimum; keys this small can be factored or broken with feasible resources.` };
}

export const ngb088 = defineRule({
  meta: {
    id: 'NGB088',
    name: 'Insufficient asymmetric key size',
    category: 'cryptography',
    defaultSeverity: 'medium',
    cwe: ['CWE-326'],
    docs: {
      description:
        'Reports generation of RSA, DSA and Diffie-Hellman keys smaller than 2048 bits and elliptic-curve keys on curves below 224 bits: Web Crypto `generateKey()` (`RSA-OAEP`, `RSA-PSS`, `RSASSA-PKCS1-v1_5`), Node `crypto.generateKeyPair(Sync)()` / `generateKeySync()`, `crypto.createDiffieHellman(primeLength)` and node-forge `pki.rsa.generateKeyPair()`.',
      rationale:
        'RSA-1024 and DH-1024 are within reach of well-funded attackers, and 512/768-bit keys have been factored publicly; NIST disallowed keys below 2048 bits (112-bit security) for new signatures and key establishment. Keys generated in the browser or on the SSR server protect signatures, encrypted payloads and key exchange for their whole lifetime — a weak key cannot be fixed later for data already protected with it.',
      patterns: [
        "`crypto.subtle.generateKey({ name: 'RSA-OAEP' | 'RSA-PSS' | 'RSASSA-PKCS1-v1_5', modulusLength }, …)` with a constant `modulusLength` < 2048",
        "`generateKeyPair(Sync)('rsa' | 'rsa-pss' | 'dsa', { modulusLength })` < 2048, `('dh', { primeLength })` < 2048, `('ec', { namedCurve })` on a curve below 224 bits (secp112/128/160/192, prime192v1, P-192, brainpoolP160/192, small binary curves)",
        '`createDiffieHellman(primeLength)` with a constant length < 2048',
        '`forge.pki.rsa.generateKeyPair(bits)` / `({ bits })` < 2048',
        'Keys ≤ 1024 bits: high severity; 1025–2047: medium',
      ],
      limitations: [
        'Key sizes of imported keys (`importKey`, PEM files, certificates) are not visible.',
        'Sizes read from configuration at runtime are not assessed.',
      ],
      falsePositives: [
        'Throwaway keys in test helpers outside excluded test folders are reported; exclude those files.',
      ],
      remediation:
        'Use RSA keys of at least 2048 bits (3072 for protection beyond 2030), Diffie-Hellman groups of at least 2048 bits, or — preferably — elliptic curves P-256 / Ed25519 / X25519.',
      example: {
        unsafe: "await crypto.subtle.generateKey({ name: 'RSA-OAEP', modulusLength: 1024, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }, true, ['encrypt', 'decrypt']);",
        safe: "await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify']);",
      },
      references: [
        { title: 'NIST SP 800-131A Rev. 2 — Transitioning cryptographic algorithms and key lengths', url: 'https://csrc.nist.gov/pubs/sp/800/131/a/r2/final' },
        { title: 'OWASP — Cryptographic Storage Cheat Sheet (algorithms)', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html#algorithms' },
      ],
    },
  },
  analyze(ctx) {
    const findings: RuleFinding[] = [];
    const push = (node: ts.Node, issue: { severity: Severity; message: string } | undefined, api: string, evidence: string) => {
      if (issue) findings.push({ node, message: `${api}: ${issue.message}`, severity: issue.severity, confidence: 'high', evidenceKind: 'pattern', evidence: [evidence] });
    };
    for (const call of ctx.index.calls) {
      const a = call.arguments;
      if (subtleCall(ctx, call, ['generateKey'])) {
        const name = algorithmName(ctx, a[0]);
        if (!name?.startsWith('RSA')) continue;
        const bits = constantNumber(ctx, objectProp(ctx, objectLiteral(ctx, a[0]), 'modulusLength'));
        if (bits !== undefined) push(call, sizeIssue(bits, RSA_MIN, `${name} modulus`), 'crypto.subtle.generateKey()', `modulusLength: ${bits}`);
        continue;
      }
      const fn = nodeCryptoCall(ctx, call, ['generateKeyPair', 'generateKeyPairSync', 'createDiffieHellman']);
      if (fn === 'createDiffieHellman') {
        const bits = constantNumber(ctx, a[0]);
        if (bits !== undefined) push(call, sizeIssue(bits, DH_MIN, 'Diffie-Hellman prime'), 'createDiffieHellman()', `primeLength: ${bits}`);
        continue;
      }
      if (fn) {
        const type = a[0] && ctx.symbols.constantString(a[0])?.toLowerCase();
        const opts = objectLiteral(ctx, a[1]);
        if (!type || !opts) continue;
        if (type === 'rsa' || type === 'rsa-pss' || type === 'dsa') {
          const bits = constantNumber(ctx, objectProp(ctx, opts, 'modulusLength'));
          if (bits !== undefined) push(call, sizeIssue(bits, RSA_MIN, `${type.toUpperCase()} modulus`), `${fn}('${type}')`, `modulusLength: ${bits}`);
        } else if (type === 'dh') {
          const bits = constantNumber(ctx, objectProp(ctx, opts, 'primeLength'));
          if (bits !== undefined) push(call, sizeIssue(bits, DH_MIN, 'Diffie-Hellman prime'), `${fn}('dh')`, `primeLength: ${bits}`);
        } else if (type === 'ec') {
          const curveExpr = objectProp(ctx, opts, 'namedCurve');
          const curve = curveExpr && ctx.symbols.constantString(curveExpr);
          if (curve && WEAK_CURVE.test(curve)) {
            findings.push({ node: call, message: `${fn}('ec') uses the curve ${curve}, which offers less than 112-bit security; use P-256 or stronger.`, severity: 'high', confidence: 'high', evidenceKind: 'pattern', evidence: [`namedCurve: ${curve}`] });
          }
        }
        continue;
      }
      // node-forge: forge.pki.rsa.generateKeyPair(1024) / ({ bits: 1024 })
      if (memberName(ctx, call.expression) === 'generateKeyPair' && /(^|\.)pki\.rsa$/.test(strip(ctx, call.expression).getText().replace(/\.generateKeyPair$/, ''))) {
        const bits = constantNumber(ctx, a[0]) ?? constantNumber(ctx, objectProp(ctx, objectLiteral(ctx, a[0]), 'bits'));
        if (bits !== undefined) push(call, sizeIssue(bits, RSA_MIN, 'RSA modulus'), 'forge.pki.rsa.generateKeyPair()', `bits: ${bits}`);
      }
    }
    return findings;
  },
});
