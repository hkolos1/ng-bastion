import { defineRule, type RuleFinding, type Severity } from '@ngbastion/plugin-api';
import { objectLiteral, objectProp } from '../shared/http.js';
import { constantNumber, kdfCalls, type KdfCall } from '../shared/crypto.js';

/** OWASP Password Storage Cheat Sheet (2023) PBKDF2 minimums. SHA-384 uses the SHA-512 figure (conservative). */
const PBKDF2_MIN: Record<string, number> = { 'SHA-1': 1_300_000, 'SHA-256': 600_000, 'SHA-384': 210_000, 'SHA-512': 210_000 };
const BCRYPT_MIN = 10;
/** scrypt: N=2^17, r=8, p=1 or an equivalent N·r·p (OWASP lists N=2^13…2^17 with p scaled up). */
const SCRYPT_MIN_NRP = 2 ** 17 * 8;
/** argon2id: m=19456 KiB, t=2 and its equivalents down to m=7168, t=5 (m·t ≥ 35840). */
const ARGON2_MIN_MEMORY = 7168;
const ARGON2_MIN_MT = 7168 * 5;

interface Weakness { message: string; severity: Severity; confidence: 'high' | 'medium'; evidence: string[] }

function assess(ctx: Parameters<typeof constantNumber>[0], k: KdfCall): Weakness | undefined {
  switch (k.kind) {
    case 'pbkdf2': {
      const n = constantNumber(ctx, k.iterations);
      if (n === undefined) return undefined;
      const hash = k.hash ?? 'SHA-256';
      const min = PBKDF2_MIN[hash] ?? PBKDF2_MIN['SHA-256']!;
      if (n >= min) return undefined;
      return {
        message: `${k.api} uses ${n.toLocaleString('en-US')} iterations of ${hash}; OWASP recommends at least ${min.toLocaleString('en-US')}. Each guess costs an attacker that little to brute-force a stolen hash.`,
        severity: n < 10_000 ? 'high' : 'medium',
        confidence: k.hash ? 'high' : 'medium',
        evidence: [`iterations: ${n}`, k.hash ? `hash: ${hash}` : 'hash not identified; assessed against the SHA-256 minimum'],
      };
    }
    case 'bcrypt': {
      const cost = constantNumber(ctx, k.cost);
      if (cost === undefined || cost >= BCRYPT_MIN) return undefined;
      return { message: `${k.api} uses bcrypt cost ${cost}; use a work factor of at least ${BCRYPT_MIN}.`, severity: cost < 8 ? 'high' : 'medium', confidence: 'high', evidence: [`cost: ${cost}`] };
    }
    case 'scrypt': {
      const o = objectLiteral(ctx, k.options);
      const read = (...keys: string[]) => keys.map((key) => objectProp(ctx, o, key)).find(Boolean);
      const nExpr = read('N', 'cost');
      const rExpr = read('r', 'blockSize');
      const pExpr = read('p', 'parallelization');
      const N = nExpr ? constantNumber(ctx, nExpr) : 16_384;
      const r = rExpr ? constantNumber(ctx, rExpr) : 8;
      const p = pExpr ? constantNumber(ctx, pExpr) : 1;
      if (N === undefined || r === undefined || p === undefined || N * r * p >= SCRYPT_MIN_NRP) return undefined;
      const defaults = !nExpr;
      return {
        message: `${k.api} runs scrypt with N=${N}, r=${r}, p=${p}${defaults ? ' (Node defaults)' : ''}; OWASP recommends N=2^17, r=8, p=1 or an equivalent cost.`,
        severity: defaults ? 'low' : 'medium',
        confidence: defaults ? 'medium' : 'high',
        evidence: [`N=${N}, r=${r}, p=${p}`, ...(defaults ? ['cost parameters not set; Node defaults to N=16384'] : [])],
      };
    }
    case 'argon2': {
      const o = objectLiteral(ctx, k.options);
      const mExpr = objectProp(ctx, o, 'memoryCost');
      const tExpr = objectProp(ctx, o, 'timeCost');
      if (!mExpr && !tExpr) return undefined; // library defaults (m=64 MiB, t=3) are fine
      const m = mExpr ? constantNumber(ctx, mExpr) : 65_536;
      const t = tExpr ? constantNumber(ctx, tExpr) : 3;
      if (m === undefined || t === undefined || (m >= ARGON2_MIN_MEMORY && m * t >= ARGON2_MIN_MT)) return undefined;
      return { message: `argon2.hash() uses memoryCost=${m} KiB, timeCost=${t}; OWASP recommends at least m=19456 KiB with t=2 (or an equivalent memory/time trade-off).`, severity: 'medium', confidence: 'high', evidence: [`memoryCost: ${m}`, `timeCost: ${t}`] };
    }
  }
}

export const ngb087 = defineRule({
  meta: {
    id: 'NGB087',
    name: 'Insufficient password-hashing work factor',
    category: 'cryptography',
    defaultSeverity: 'medium',
    cwe: ['CWE-916', 'CWE-326'],
    docs: {
      description:
        'Reports password hashing / key derivation configured with constant work factors below the OWASP Password Storage Cheat Sheet minimums: PBKDF2 iterations (Web Crypto, Node `crypto`, CryptoJS), bcrypt cost, scrypt N·r·p (Node `crypto.scrypt`, including its default N=16384) and argon2 memory / time cost.',
      rationale:
        'Password hashes are meant to be slow so that an attacker who steals the database (or a client-side encrypted vault) can test only a few guesses per second. PBKDF2 with 1,000 or 10,000 iterations — common in old tutorials — lets a single GPU test billions of candidates; the same applies to bcrypt costs below 10 and memory-light scrypt / argon2 settings. Keys derived from passwords for client-side encryption have the same problem.',
      patterns: [
        'PBKDF2 `iterations` constant below 1,300,000 (SHA-1), 600,000 (SHA-256), 210,000 (SHA-384 / SHA-512); an unidentified hash is assessed against the SHA-256 minimum with medium confidence. Below 10,000: high severity',
        '`bcrypt.hash(pw, cost)`, `hashSync`, `genSalt(cost)`, `genSaltSync(cost)` with cost < 10 (bcrypt, bcryptjs)',
        '`crypto.scrypt(Sync)(pw, salt, len, { N | cost, r | blockSize, p | parallelization })` with N·r·p below 2^17·8; omitted options (Node default N=16384) are reported with low severity',
        '`argon2.hash(pw, { memoryCost, timeCost })` with memoryCost < 7168 KiB or memoryCost·timeCost < 35840',
        'Constants include literals, arithmetic (`2 ** 14`, `1 << 14`, `Math.pow`), `const` values and config-object properties',
      ],
      limitations: [
        'Work factors read from environment variables or runtime configuration are not assessed.',
        'Hashing libraries other than the ones listed are not analyzed.',
      ],
      falsePositives: [
        'PBKDF2 used to derive keys from high-entropy secrets (not human passwords) does not need password-grade iteration counts but is still reported; document an exception.',
      ],
      remediation:
        'Prefer argon2id (m ≥ 19 MiB, t ≥ 2) or scrypt (N = 2^17, r = 8, p = 1). Where PBKDF2 is required, use ≥ 600,000 iterations with SHA-256 (≥ 210,000 with SHA-512); bcrypt needs a cost of at least 10. Re-hash existing passwords at the next login.',
      example: {
        unsafe: "await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations: 1000 }, key, 256);",
        safe: "await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations: 600_000 }, key, 256);",
      },
      references: [
        { title: 'OWASP — Password Storage Cheat Sheet', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html' },
        { title: 'RFC 9106 — Argon2', url: 'https://www.rfc-editor.org/rfc/rfc9106' },
      ],
    },
  },
  analyze(ctx) {
    const findings: RuleFinding[] = [];
    for (const k of kdfCalls(ctx)) {
      const w = assess(ctx, k);
      if (w) findings.push({ node: k.node, message: w.message, confidence: w.confidence, severity: w.severity, evidenceKind: 'pattern', evidence: w.evidence });
    }
    return findings;
  },
});
