import { defineRule, type RuleFinding } from '@ngbastion/plugin-api';
import { constantBytes, kdfCalls } from '../shared/crypto.js';

export const ngb086 = defineRule({
  meta: {
    id: 'NGB086',
    name: 'Static password-hashing salt',
    category: 'cryptography',
    defaultSeverity: 'medium',
    cwe: ['CWE-760', 'CWE-916'],
    docs: {
      description:
        'Reports password hashing / key derivation whose salt is a compile-time constant: Web Crypto PBKDF2 (`deriveBits` / `deriveKey`), Node `crypto.pbkdf2(Sync)` and `crypto.scrypt(Sync)`, `CryptoJS.PBKDF2`, `bcrypt.hash(password, "<constant salt>")` and `argon2.hash(password, { salt })`.',
      rationale:
        'A salt exists so that equal passwords produce different hashes and an attacker cannot reuse one precomputed (rainbow) table or one brute-force run for every user. A constant salt — the same string or byte array for every password — removes that: every user with the password "Summer2024!" gets the same hash, and one cracking run attacks all accounts at once. Keys derived from a password with a fixed salt are likewise identical across users and installations.',
      patterns: [
        "`crypto.subtle.deriveBits({ name: 'PBKDF2', salt, … })` / `deriveKey(…)` on `SubtleCrypto`",
        '`pbkdf2(pw, salt, …)`, `pbkdf2Sync(…)`, `scrypt(pw, salt, …)`, `scryptSync(…)` from `crypto` / `node:crypto` (named, namespace, default or `require()` bindings)',
        '`CryptoJS.PBKDF2(pw, salt, …)`, `bcrypt.hash(pw, salt)` / `hashSync` (bcrypt, bcryptjs) with a string salt, `argon2.hash(pw, { salt })`',
        "Constant salts: string literals / `const` strings, `new TextEncoder().encode('…')`, `Buffer.from('…')`, literal byte arrays, zero-filled buffers (`new Uint8Array(16)`), and `const` / readonly / config-object bindings of those",
      ],
      limitations: [
        'Salts derived deterministically from user data (e-mail, username) are predictable but not constant and are not reported.',
        'A random salt generated once at module level and reused for every user is not reported.',
        'Hashing done by other libraries (node-forge, libsodium wrappers) is not analyzed.',
      ],
      falsePositives: [
        'Deriving an application-wide key (not a per-user password hash) from a secret passphrase with a fixed salt is reported; such keys should still use a random salt stored next to the ciphertext.',
      ],
      remediation:
        'Generate a fresh random salt per password (`crypto.getRandomValues(new Uint8Array(16))`, `crypto.randomBytes(16)`, `bcrypt.genSalt()`) and store it with the hash. Better: let the library manage salts (`bcrypt.hash(pw, 12)`, `argon2.hash(pw)`).',
      example: {
        unsafe: "const hash = crypto.pbkdf2Sync(password, 'ngbastion-salt', 600000, 32, 'sha256');",
        safe: "const salt = crypto.randomBytes(16);\nconst hash = crypto.pbkdf2Sync(password, salt, 600000, 32, 'sha256');",
      },
      references: [
        { title: 'OWASP — Password Storage Cheat Sheet (salting)', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#salting' },
        { title: 'NIST SP 800-132 — Recommendation for Password-Based Key Derivation', url: 'https://csrc.nist.gov/pubs/sp/800/132/final' },
      ],
    },
  },
  analyze(ctx) {
    const findings: RuleFinding[] = [];
    for (const k of kdfCalls(ctx)) {
      if (!k.salt || !constantBytes(ctx, k.salt)) continue;
      findings.push({
        node: k.node,
        message: `${k.api} uses a constant salt; equal passwords produce equal hashes, so one precomputed table or cracking run attacks every user.`,
        confidence: 'high',
        evidenceKind: 'pattern',
        evidence: [`salt: ${k.salt.getText().slice(0, 80)}`],
      });
    }
    return findings;
  },
});
