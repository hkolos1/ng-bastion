import type * as ts from 'typescript';
import { defineRule, type AnalysisContext, type RuleFinding, type Severity } from '@ngbastion/plugin-api';
import { memberName, receiverOf, strip } from '../shared/common.js';
import { objectLiteral, objectProp } from '../shared/http.js';
import { moduleCall, nodeModules } from '../shared/server.js';

interface Weakness {
  severity: Severity;
  why: string;
}

/** Classifies an OpenSSL / node-forge cipher name. */
export function cipherWeakness(name: string): Weakness | undefined {
  const n = name.toLowerCase();
  if (/^(des-ede3?|des3|3des|tripledes)(-|$)/.test(n)) return { severity: 'medium', why: 'Triple DES has a 64-bit block (Sweet32 collisions after ~32 GB) and is withdrawn by NIST' };
  if (/^desx?(-|$)/.test(n)) return { severity: 'high', why: 'DES has a 56-bit key that can be brute-forced' };
  if (/^rc4(-\d+|-hmac-md5)?$|^arcfour/.test(n)) return { severity: 'high', why: 'RC4 has exploitable keystream biases' };
  if (/^rc2/.test(n)) return { severity: 'high', why: 'RC2 is a broken 64-bit block cipher' };
  if (/^(bf|blowfish|cast5?|idea|seed)(-|$)/.test(n)) return { severity: 'medium', why: `${name} is a legacy 64-bit block cipher (Sweet32)` };
  if (/-ecb$|^aes-ecb$/.test(n)) return { severity: 'medium', why: 'ECB mode encrypts equal blocks to equal ciphertext and leaks patterns of the plaintext' };
  return undefined;
}

const CRYPTOJS_WEAK: Record<string, Weakness> = {
  DES: { severity: 'high', why: 'DES has a 56-bit key that can be brute-forced' },
  TripleDES: { severity: 'medium', why: 'Triple DES has a 64-bit block (Sweet32) and is withdrawn by NIST' },
  RC4: { severity: 'high', why: 'RC4 has exploitable keystream biases' },
  RC4Drop: { severity: 'high', why: 'RC4 has exploitable keystream biases' },
};

const NODE_CRYPTO = nodeModules('crypto');

function isCryptoJs(ctx: AnalysisContext, e: ts.Expression | undefined): boolean {
  if (!e) return false;
  const x = strip(ctx, e);
  const o = ctx.symbols.typeOrigin(x);
  if (o && /^crypto-js(\/|$)/.test(o.module)) return true;
  return ctx.ts.isIdentifier(x) && x.text === 'CryptoJS';
}

export const ngb065 = defineRule({
  meta: {
    id: 'NGB065',
    name: 'Broken or weak cipher',
    category: 'cryptography',
    defaultSeverity: 'high',
    cwe: ['CWE-327'],
    docs: {
      description:
        "Reports encryption with broken or obsolete ciphers and modes: DES, RC4, RC2 (high), Triple DES, Blowfish, CAST, IDEA and ECB mode (medium) in Node `createCipheriv()` / `createDecipheriv()`, CryptoJS (`CryptoJS.DES` / `TripleDES` / `RC4` / `RC4Drop`, `mode: CryptoJS.mode.ECB`) and node-forge (`forge.cipher.createCipher('DES-…' | 'AES-ECB', key)`), plus the deprecated Node `createCipher()` / `createDecipher()` API (no IV, MD5-based key derivation).",
      rationale:
        "DES keys are brute-forced in hours, RC4 keystreams are biased enough to recover plaintext, 64-bit block ciphers leak plaintext after a few gigabytes under one key (Sweet32), and ECB mode shows which blocks are equal — the classic 'ECB penguin'. `crypto.createCipher()` derives the key from a password with a single MD5 round and uses no IV, so the same plaintext always produces the same ciphertext.",
      patterns: [
        "`createCipheriv('des-ede3-cbc' | 'des-cbc' | 'rc4' | 'bf-cbc' | 'aes-256-ecb' …, key, iv)` and `createDecipheriv(…)` from `crypto` / `node:crypto` (named, namespace, default and `require()` bindings)",
        '`crypto.createCipher(alg, password)` / `createDecipher()` (deprecated) — medium',
        '`CryptoJS.DES.encrypt()`, `CryptoJS.TripleDES.encrypt()`, `CryptoJS.RC4.encrypt()`, `{ mode: CryptoJS.mode.ECB }`',
        "`forge.cipher.createCipher('DES-CBC' | '3DES-CBC' | 'AES-ECB', key)`",
      ],
      limitations: [
        'Algorithm names must be compile-time constants; names read from configuration are not resolved.',
        'Unauthenticated modes (AES-CBC, AES-CTR without a MAC) are not reported.',
      ],
      falsePositives: [
        'Decrypting legacy data for migration is reported; once re-encrypted with AES-GCM the code can be removed or the finding excepted.',
      ],
      remediation:
        "Use an authenticated cipher: AES-256-GCM or ChaCha20-Poly1305 (`createCipheriv('aes-256-gcm', key, randomBytes(12))`, Web Crypto `AES-GCM`) with a random IV per message, and derive keys with a real KDF (scrypt, PBKDF2, HKDF) instead of `createCipher()`.",
      example: {
        unsafe: `const cipher = createCipheriv('des-ede3-cbc', key, iv);`,
        safe: `const iv = randomBytes(12);
const cipher = createCipheriv('aes-256-gcm', key, iv);`,
      },
      references: [
        { title: 'OWASP — Cryptographic Storage Cheat Sheet (algorithms)', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html#algorithms' },
        { title: 'NIST SP 800-131A Rev. 2 — Transitioning cryptographic algorithms', url: 'https://csrc.nist.gov/pubs/sp/800/131/a/r2/final' },
        { title: 'Sweet32 — birthday attacks on 64-bit block ciphers', url: 'https://sweet32.info/' },
      ],
    },
  },
  analyze(ctx) {
    const t = ctx.ts;
    const findings: RuleFinding[] = [];
    const push = (node: ts.Node, api: string, w: Weakness, evidence: string) =>
      findings.push({ node, message: `${api}: ${w.why}. Use AES-GCM or ChaCha20-Poly1305.`, confidence: 'high', severity: w.severity, evidenceKind: 'pattern', evidence: [evidence] });
    for (const call of ctx.index.calls) {
      const a = call.arguments;
      const node = moduleCall(ctx, call, NODE_CRYPTO, ['createCipheriv', 'createDecipheriv', 'createCipher', 'createDecipher']);
      if (node && a[0]) {
        const alg = ctx.symbols.constantString(a[0]);
        const w = alg ? cipherWeakness(alg) : undefined;
        if (w) push(call, `${node}('${alg}')`, w, `algorithm: ${alg}`);
        else if (node === 'createCipher' || node === 'createDecipher') {
          push(call, `crypto.${node}()`, { severity: 'medium', why: 'the deprecated API derives the key with a single MD5 round and uses no IV, so encryption is deterministic and the password is cheap to brute-force' }, `${node}(${alg ?? '…'})`);
        }
        continue;
      }
      const callee = strip(ctx, call.expression);
      const name = memberName(ctx, callee);
      const recv = receiverOf(ctx, callee);
      if (!name || !recv) continue;
      // CryptoJS.DES.encrypt(...)
      if ((name === 'encrypt' || name === 'decrypt') && t.isPropertyAccessExpression(strip(ctx, recv))) {
        const algo = (strip(ctx, recv) as ts.PropertyAccessExpression).name.text;
        if (Object.hasOwn(CRYPTOJS_WEAK, algo) && isCryptoJs(ctx, (strip(ctx, recv) as ts.PropertyAccessExpression).expression)) {
          push(call, `CryptoJS.${algo}.${name}()`, CRYPTOJS_WEAK[algo]!, `cipher: ${algo}`);
          continue;
        }
        // CryptoJS.AES.encrypt(m, k, { mode: CryptoJS.mode.ECB })
        const mode = objectProp(ctx, objectLiteral(ctx, a[2]), 'mode');
        const m = mode && strip(ctx, mode);
        if (m && t.isPropertyAccessExpression(m) && m.name.text === 'ECB' && memberName(ctx, m.expression) === 'mode') {
          push(call, `CryptoJS.${algo}.${name}() with mode ECB`, { severity: 'medium', why: 'ECB mode encrypts equal blocks to equal ciphertext and leaks patterns of the plaintext' }, 'mode: CryptoJS.mode.ECB');
          continue;
        }
      }
      // forge.cipher.createCipher('DES-CBC', key)
      if ((name === 'createCipher' || name === 'createDecipher') && memberName(ctx, recv) === 'cipher' && a[0]) {
        const alg = ctx.symbols.constantString(a[0]);
        const w = alg ? cipherWeakness(alg.replace(/^3des/i, 'des-ede3')) : undefined;
        if (w) push(call, `forge.cipher.${name}('${alg}')`, w, `algorithm: ${alg}`);
      }
    }
    return findings;
  },
});
