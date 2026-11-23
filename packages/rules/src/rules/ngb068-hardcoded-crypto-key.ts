import type * as ts from 'typescript';
import { defineRule, type AnalysisContext, type RuleFinding } from '@ngbastion/plugin-api';
import { is, memberName, receiverOf, strip } from '../shared/common.js';
import { objectLiteral, objectProp } from '../shared/http.js';
import { moduleCall, nodeModules } from '../shared/server.js';
import { constantBytes } from '../shared/crypto.js';

const NODE_CRYPTO = nodeModules('crypto');
const JWT_MODULES = ['jsonwebtoken'];
const CRYPTOJS_CIPHERS = new Set(['AES', 'DES', 'TripleDES', 'Rabbit', 'RC4', 'RC4Drop']);

/** JWK object literal with constant secret members (`k` for oct keys, `d` for private keys). */
function constantJwk(ctx: AnalysisContext, e: ts.Expression): boolean {
  const o = objectLiteral(ctx, e);
  if (!o) return false;
  const secret = objectProp(ctx, o, 'k') ?? objectProp(ctx, o, 'd');
  return !!secret && ctx.symbols.constantString(secret) !== undefined;
}

function isCryptoJs(ctx: AnalysisContext, e: ts.Expression): boolean {
  const x = strip(ctx, e);
  const o = ctx.symbols.typeOrigin(x);
  return (!!o && /^crypto-js(\/|$)/.test(o.module)) || (ctx.ts.isIdentifier(x) && x.text === 'CryptoJS');
}

export const ngb068 = defineRule({
  meta: {
    id: 'NGB068',
    name: 'Hardcoded cryptographic key',
    category: 'cryptography',
    defaultSeverity: 'high',
    cwe: ['CWE-321', 'CWE-798'],
    docs: {
      description:
        "Reports compile-time constant keys passed to cryptographic APIs: Web Crypto `importKey('raw' | 'jwk', …)`, Node `createCipheriv()` / `createDecipheriv()` / `createHmac()` / `createSecretKey()`, CryptoJS ciphers and HMACs (`CryptoJS.AES.encrypt(data, 'passphrase')`, `CryptoJS.HmacSHA256(msg, 'key')`) and `jsonwebtoken` `sign()` / `verify()` secrets. A key is constant when it is a string literal / `const`, `TextEncoder().encode('…')`, `Buffer.from('…')`, `CryptoJS.enc.Utf8.parse('…')`, a literal byte array, or a JWK literal with a constant `k` / `d` member.",
      rationale:
        "A key in the source is a key everybody has: it ships in the JavaScript bundle (for browser code), lives forever in Git history, is shared by every environment, and cannot be rotated without a release. Anything \"encrypted\" with it — tokens in storage, signed JWTs, HMAC-protected webhooks — can be decrypted or forged by anyone who reads the bundle or the repository. NGB018 finds secret-looking literals by name and format; this rule finds keys by where they are used, regardless of their name.",
      patterns: [
        "`crypto.subtle.importKey('raw', new TextEncoder().encode('k'), …)`, `importKey('jwk', { kty: 'oct', k: '…' }, …)`",
        "`createCipheriv(alg, 'key…', iv)`, `createDecipheriv(…)`, `createHmac('sha256', 'secret')`, `createSecretKey(Buffer.from('…'))` from `crypto` / `node:crypto`",
        "`CryptoJS.AES.encrypt(data, 'passphrase')` / `decrypt()`, `CryptoJS.HmacSHA256(msg, 'key')` and other `Hmac*` functions",
        "`jwt.sign(payload, 'secret')` / `jwt.verify(token, 'secret')` (`jsonwebtoken`)",
      ],
      limitations: [
        'Keys loaded from bundled JSON / environment files at build time (`environment.ts`) are not followed; NGB018 reports secret-looking values there.',
        'Constant-ness is followed through `const` variables only, not through class fields or function returns.',
      ],
      falsePositives: [
        'Test vectors and demo code are reported unless excluded (`**/*.spec.ts` is excluded by the presets).',
        'Public keys imported as constants (`spki`) are not reported; private keys and symmetric keys are.',
      ],
      remediation:
        'Do not embed keys. In browser code, assume anything in the bundle is public: let the server hold keys and perform the operation, or derive per-user keys from the user\'s password with PBKDF2 / Argon2. In server code, load keys from a secret manager or environment variable at runtime and rotate them.',
      example: {
        unsafe: `const key = await crypto.subtle.importKey('raw', new TextEncoder().encode('0123456789abcdef'), 'AES-GCM', false, ['encrypt']);`,
        safe: `const key = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);`,
      },
      references: [
        { title: 'CWE-321: Use of Hard-coded Cryptographic Key', url: 'https://cwe.mitre.org/data/definitions/321.html' },
        { title: 'OWASP — Cryptographic Storage Cheat Sheet (key management)', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html#key-management' },
      ],
    },
  },
  analyze(ctx) {
    const t = ctx.ts;
    const findings: RuleFinding[] = [];
    const push = (node: ts.Node, api: string, key: ts.Expression) =>
      findings.push({
        node,
        message: `${api} uses a hardcoded key; anyone with the bundle or the repository can decrypt or forge the protected data.`,
        confidence: 'high',
        evidenceKind: 'pattern',
        evidence: [`key expression: ${strip(ctx, key).getText().replace(/(['"`])[^'"`]{4,}\1/g, '$1…$1').slice(0, 60)}`],
        redactSnippet: true,
      });
    for (const call of ctx.index.calls) {
      const a = call.arguments;
      const info = ctx.symbols.callee(call);
      if (info?.declaration) continue;
      // Web Crypto importKey
      if (info?.name === 'importKey' && is(info.receiver, 'dom', 'SubtleCrypto') && a[0] && a[1]) {
        const format = ctx.symbols.constantString(a[0]);
        if ((format === 'raw' && constantBytes(ctx, a[1])) || (format === 'jwk' && constantJwk(ctx, a[1])) || (format === 'pkcs8' && constantBytes(ctx, a[1]))) push(call, `crypto.subtle.importKey('${format}')`, a[1]);
        continue;
      }
      const node = moduleCall(ctx, call, NODE_CRYPTO, ['createCipheriv', 'createDecipheriv', 'createHmac', 'createSecretKey']);
      if (node) {
        const key = node === 'createSecretKey' ? a[0] : a[1];
        if (key && constantBytes(ctx, key)) push(call, `${node}()`, key);
        continue;
      }
      const jwt = moduleCall(ctx, call, JWT_MODULES, ['sign', 'verify']);
      if (jwt && a[1] && constantBytes(ctx, a[1])) {
        push(call, `jsonwebtoken ${jwt}()`, a[1]);
        continue;
      }
      const callee = strip(ctx, call.expression);
      const name = memberName(ctx, callee);
      const recv = receiverOf(ctx, callee);
      if (!name || !recv) continue;
      // CryptoJS.AES.encrypt(data, key)
      if ((name === 'encrypt' || name === 'decrypt') && t.isPropertyAccessExpression(strip(ctx, recv))) {
        const r = strip(ctx, recv) as ts.PropertyAccessExpression;
        if (CRYPTOJS_CIPHERS.has(r.name.text) && isCryptoJs(ctx, r.expression) && a[1] && constantBytes(ctx, a[1])) push(call, `CryptoJS.${r.name.text}.${name}()`, a[1]);
      } else if (/^Hmac(MD5|SHA1|SHA224|SHA256|SHA384|SHA512|SHA3|RIPEMD160)$/.test(name) && isCryptoJs(ctx, recv) && a[1] && constantBytes(ctx, a[1])) {
        push(call, `CryptoJS.${name}()`, a[1]);
      }
    }
    return findings;
  },
});
