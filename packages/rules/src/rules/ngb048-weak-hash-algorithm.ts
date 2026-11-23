import type * as ts from 'typescript';
import { defineRule, type AnalysisContext, type RuleFinding, type Severity } from '@ngbastion/plugin-api';
import { is, storedName, strip } from '../shared/common.js';
import { objectLiteral, objectProp } from '../shared/http.js';
import { classifyName, words } from '../shared/sensitivity.js';

const WEAK = /^(md2|md4|md5|sha-?1|sha1|ripemd-?160)$/i;
const PURPOSE = new Set(['password', 'passwd', 'pwd', 'passphrase', 'pin', 'otp', 'secret', 'signature', 'sign', 'signing', 'verify', 'verification', 'integrity', 'auth', 'authenticate', 'hmac', 'mac', 'credential', 'credentials', 'token', 'apikey', 'csrf', 'nonce', 'challenge', 'verifier', 'session', 'checksum']);
const MD5_PACKAGES = ['md5', 'js-md5', 'blueimp-md5', 'crypto-js/md5', 'crypto-js/sha1', 'js-sha1', 'sha1'];

/** Names that say what the digest is for: hashed value, result variable, enclosing function. */
function purpose(ctx: AnalysisContext, call: ts.CallExpression, input: ts.Expression | undefined): { term: string; password: boolean } | undefined {
  const t = ctx.ts;
  const names: string[] = [];
  if (input) {
    const x = strip(ctx, input);
    const inner = t.isCallExpression(x) && x.arguments[0] ? strip(ctx, x.arguments[0]) : x; // encode(password)
    for (const e of [x, inner]) {
      if (t.isIdentifier(e)) names.push(e.text);
      else if (t.isPropertyAccessExpression(e)) names.push(e.name.text);
    }
  }
  let n: ts.Node = call;
  while (n.parent && (t.isAwaitExpression(n.parent) || t.isPropertyAccessExpression(n.parent) || t.isCallExpression(n.parent) || t.isParenthesizedExpression(n.parent))) n = n.parent;
  const stored = storedName(ctx, n);
  if (stored) names.push(stored);
  const fn = ctx.flow.enclosingFunction(call);
  if (fn?.name && t.isIdentifier(fn.name)) names.push(fn.name.text);
  else if (fn && t.isVariableDeclaration(fn.parent) && t.isIdentifier(fn.parent.name)) names.push(fn.parent.name.text);
  for (const name of names) {
    const w = words(name);
    if (w.some((x) => ['password', 'passwd', 'pwd', 'passphrase', 'pin'].includes(x))) return { term: name, password: true };
    if (w.some((x) => PURPOSE.has(x)) || classifyName(name)?.category === 'credential') return { term: name, password: false };
  }
  return undefined;
}

export const ngb048 = defineRule({
  meta: {
    id: 'NGB048',
    name: 'Weak hash algorithm',
    category: 'cryptography',
    defaultSeverity: 'medium',
    cwe: ['CWE-328', 'CWE-327', 'CWE-916'],
    docs: {
      description:
        "Reports MD5, SHA-1, MD4 and RIPEMD-160 used for security purposes: `crypto.subtle.digest('SHA-1', …)`, Web Crypto signing / HMAC keys with `hash: 'SHA-1'`, CryptoJS `MD5()` / `SHA1()`, md5 / sha1 npm packages, and Node `createHash('md5' | 'sha1')` in SSR code. Only reported when the hashed value, the result or the enclosing function is named like a password, token, secret, signature, integrity check, OTP or session value; password hashing is high severity.",
      rationale:
        "MD5 and SHA-1 have practical collision attacks, so signatures and integrity checks based on them can be forged. Hashing passwords on the client with any fast hash (and MD5/SHA-1 in particular) does not protect them: the hash becomes the password, and fast hashes are brute-forced at billions of guesses per second. Non-security checksums (cache keys, Gravatar URLs) are not reported.",
      patterns: [
        "`crypto.subtle.digest('SHA-1' | { name: 'SHA-1' }, data)` (DOM `SubtleCrypto`)",
        "`crypto.subtle.importKey/generateKey(…, { name: 'HMAC' | 'RSASSA-PKCS1-v1_5' | 'RSA-PSS' | 'ECDSA', hash: 'SHA-1' }, …)`",
        '`CryptoJS.MD5(x)`, `CryptoJS.SHA1(x)`, `CryptoJS.HmacMD5/HmacSHA1`, default imports of `md5`, `js-md5`, `blueimp-md5`, `crypto-js/md5`, `crypto-js/sha1`, `js-sha1`',
        "`createHash('md5' | 'sha1')` from `crypto` / `node:crypto`",
        'Purpose names: password, pin, passphrase (high severity); signature, integrity, verify, hmac, token, secret, otp, nonce, csrf, session, credential names (medium)',
      ],
      limitations: [
        'Digests whose purpose is not visible in names (passed straight into a helper with a neutral name) are not reported.',
        'Strong hashes used for password storage on the client (SHA-256 of a password) are not reported by this rule.',
      ],
      falsePositives: [
        'A value named like a secret that is only used as a non-security cache key can be reported.',
      ],
      remediation:
        "Use SHA-256 or stronger for integrity and signatures (`crypto.subtle.digest('SHA-256', …)`, HMAC-SHA-256, ECDSA P-256 with SHA-256). Never hash passwords in the browser as a protection measure: send them over TLS and hash on the server with Argon2id, scrypt or bcrypt.",
      example: {
        unsafe: `const hashed = CryptoJS.MD5(password).toString();
this.http.post('/api/login', { username, password: hashed });`,
        safe: `this.http.post('/api/login', { username, password }); // server: argon2id(password)`,
      },
      references: [
        { title: 'OWASP — Password Storage Cheat Sheet', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html' },
        { title: 'NIST SP 800-131A — Transitioning cryptographic algorithms (SHA-1)', url: 'https://csrc.nist.gov/pubs/sp/800/131/a/r2/final' },
      ],
    },
  },
  analyze(ctx) {
    const t = ctx.ts;
    const findings: RuleFinding[] = [];
    const report = (call: ts.CallExpression, algo: string, input: ts.Expression | undefined, api: string) => {
      const p = purpose(ctx, call, input);
      if (!p) return;
      const severity: Severity = p.password ? 'high' : 'medium';
      findings.push({
        node: call,
        message: p.password
          ? `${api} hashes '${p.term}' with ${algo}; fast, broken hashes do not protect passwords (the hash can be replayed and brute-forced).`
          : `${api} uses ${algo} for '${p.term}'; ${algo} has practical collision attacks and must not protect integrity or authentication.`,
        confidence: 'medium',
        severity,
        evidenceKind: 'heuristic',
        evidence: [`algorithm: ${algo}`, `purpose inferred from name '${p.term}'`],
      });
    };
    for (const call of ctx.index.calls) {
      const info = ctx.symbols.callee(call);
      if (!info || info.declaration) continue;
      const a = call.arguments;
      if (is(info.receiver, 'dom', 'SubtleCrypto')) {
        if (info.name === 'digest' && a[0]) {
          const algo = ctx.symbols.constantString(objectProp(ctx, objectLiteral(ctx, a[0]), 'name') ?? a[0]);
          if (algo && WEAK.test(algo)) report(call, algo.toUpperCase(), a[1], 'crypto.subtle.digest()');
        } else if (['importKey', 'generateKey', 'deriveKey'].includes(info.name)) {
          for (const arg of a) {
            const hash = objectProp(ctx, objectLiteral(ctx, arg), 'hash');
            const algo = hash && ctx.symbols.constantString(objectProp(ctx, objectLiteral(ctx, hash), 'name') ?? hash);
            if (algo && WEAK.test(algo)) {
              findings.push({ node: call, message: `crypto.subtle.${info.name}() configures ${algo.toUpperCase()} as the hash of a signing/MAC/derivation algorithm; use SHA-256 or stronger.`, confidence: 'high', severity: 'medium', evidenceKind: 'pattern', evidence: [`hash: ${algo}`] });
              break;
            }
          }
        }
        continue;
      }
      // CryptoJS.MD5(x) / CryptoJS.SHA1(x) / CryptoJS.HmacSHA1(x, k)
      const callee = strip(ctx, call.expression);
      if (/^(MD5|SHA1|HmacMD5|HmacSHA1|RIPEMD160)$/.test(info.name) && (is(info.receiver, ['crypto-js']) || (t.isPropertyAccessExpression(callee) && /^CryptoJS$/.test(callee.expression.getText())))) {
        report(call, info.name.replace(/^Hmac/, 'HMAC-'), a[0], `CryptoJS.${info.name}()`);
      } else if (is(info.origin, MD5_PACKAGES) || (t.isIdentifier(callee) && info.origin && MD5_PACKAGES.includes(info.origin.module))) {
        report(call, /sha1/.test(info.origin!.module) ? 'SHA-1' : 'MD5', a[0], `${info.origin!.module}()`);
      } else if (info.name === 'createHash' && a[0] && (is(info.origin, ['crypto', 'node:crypto']) || is(info.receiver, ['crypto', 'node:crypto']))) {
        const algo = ctx.symbols.constantString(a[0]);
        if (algo && WEAK.test(algo)) {
          // createHash('md5').update(x).digest() → the hashed input is the update() argument.
          const update = t.isPropertyAccessExpression(call.parent) && call.parent.name.text === 'update' && t.isCallExpression(call.parent.parent) ? call.parent.parent.arguments[0] : undefined;
          report(call, algo.toUpperCase(), update, `createHash('${algo}')`);
        }
      }
    }
    return findings;
  },
});
