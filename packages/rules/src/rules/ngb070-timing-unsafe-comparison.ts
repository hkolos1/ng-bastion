import type * as ts from 'typescript';
import { defineRule, type AnalysisContext, type RuleFinding } from '@ngbastion/plugin-api';
import { codeFiles, memberName, strip } from '../shared/common.js';
import { isServerFile, moduleCall, nodeModules, requestDerived } from '../shared/server.js';
import { classifyName, directNames, words } from '../shared/sensitivity.js';

const MAC_WORDS = new Set(['signature', 'hmac', 'mac', 'digest']);
const NODE_CRYPTO = nodeModules('crypto');

/** Why `e` is a secret or an expected MAC: computed with createHmac/createHash, or named like one. */
function secretSide(ctx: AnalysisContext, e: ts.Expression, depth = 0): string | undefined {
  const t = ctx.ts;
  const x = strip(ctx, e);
  // createHmac('sha256', key).update(body).digest('hex')
  let found: string | undefined;
  const visit = (n: ts.Node): void => {
    if (found) return;
    if (t.isCallExpression(n)) {
      const m = moduleCall(ctx, n, NODE_CRYPTO, ['createHmac', 'createHash']);
      if (m) {
        found = `computed with ${m}()`;
        return;
      }
    }
    t.forEachChild(n, visit);
  };
  visit(x);
  if (found) return found;
  if (t.isIdentifier(x) && depth < 2) {
    const d = ctx.symbols.declarationOf(x);
    if (d && t.isVariableDeclaration(d) && d.initializer) {
      const inner = secretSide(ctx, d.initializer, depth + 1);
      if (inner) return inner;
    }
  }
  for (const n of directNames(ctx, x)) {
    const w = words(n);
    if (w.some((x) => MAC_WORDS.has(x)) && !/(header|name|algorithm|alg|length|type|version|key)$/i.test(n)) return `named '${n}'`;
    const c = classifyName(n);
    if (c?.category === 'credential' && c.strength === 'strong' && !/password|passwd|pwd|passphrase/i.test(n)) return `named '${n}'`;
  }
  return undefined;
}

const EQUALITY = new Set(['===', '!==', '==', '!=']);

export const ngb070 = defineRule({
  meta: {
    id: 'NGB070',
    name: 'Timing-unsafe secret comparison',
    category: 'ssr',
    defaultSeverity: 'medium',
    cwe: ['CWE-208'],
    docs: {
      description:
        "Reports server-side code that compares a value from the incoming request (header, body, query, cookies) with a secret or an expected MAC using `===`, `!==`, `==` or `!=`: webhook signatures checked against `createHmac(…).digest()`, API keys, bearer / access tokens and shared secrets. Only server files (SSR entry points, files importing Node / Express modules) are analyzed; comparisons with `crypto.timingSafeEqual()` are the safe form and are not reported.",
      rationale:
        "String equality stops at the first differing character, so the response time leaks how many leading characters of the guess were right. Over many requests — especially from the same data center — an attacker recovers a valid HMAC signature or API key byte by byte without ever knowing the secret. Webhook endpoints and internal API-key checks in SSR / BFF servers are the typical place for this bug.",
      patterns: [
        '`req.headers["x-signature"] === createHmac("sha256", secret).update(body).digest("hex")` (directly or through `const` variables)',
        '`if (req.get("x-api-key") !== process.env.API_KEY)`, `req.body.token == expectedToken`, comparisons with values named `signature`, `hmac`, `digest`, `apiKey`, `accessToken`, `secret`',
        'Requests: Express / Node request objects, including untyped `(req, res)` handlers',
      ],
      limitations: [
        'Password checks (`user.password === req.body.password`) are not reported here: plaintext password storage is the larger problem.',
        'Secrets that reach the comparison through function calls or class fields with neutral names are not recognized.',
      ],
      falsePositives: [
        'Comparisons with values that are not secret despite their names (public key IDs, signature algorithm names) may be reported; rename or except them.',
      ],
      remediation:
        "Compare secrets in constant time: convert both sides to equal-length buffers and use `crypto.timingSafeEqual(a, b)` after checking `a.length === b.length`, or compare HMACs of both values. Prefer verifying signatures with the provider SDK, which already does this.",
      example: {
        unsafe: `if (req.get('x-hub-signature-256') !== 'sha256=' + createHmac('sha256', secret).update(raw).digest('hex')) return res.sendStatus(401);`,
        safe: `const expected = Buffer.from('sha256=' + createHmac('sha256', secret).update(raw).digest('hex'));
const given = Buffer.from(req.get('x-hub-signature-256') ?? '');
if (given.length !== expected.length || !timingSafeEqual(given, expected)) return res.sendStatus(401);`,
      },
      references: [
        { title: 'Node.js — crypto.timingSafeEqual()', url: 'https://nodejs.org/api/crypto.html#cryptotimingsafeequala-b' },
        { title: 'CWE-208: Observable Timing Discrepancy', url: 'https://cwe.mitre.org/data/definitions/208.html' },
      ],
    },
  },
  analyze(ctx) {
    const t = ctx.ts;
    const findings: RuleFinding[] = [];
    for (const sf of codeFiles(ctx)) {
      if (!isServerFile(ctx, sf)) continue;
      const visit = (n: ts.Node): void => {
        if (t.isBinaryExpression(n) && EQUALITY.has(n.operatorToken.getText())) {
          const sides: [ts.Expression, ts.Expression][] = [[n.left, n.right], [n.right, n.left]];
          for (const [req, other] of sides) {
            const o = strip(ctx, other);
            if (t.isLiteralExpression(o) || o.kind === t.SyntaxKind.NullKeyword || o.kind === t.SyntaxKind.UndefinedKeyword || (t.isIdentifier(o) && o.text === 'undefined')) continue;
            if (ctx.symbols.constantString(o) !== undefined) continue;
            const from = requestDerived(ctx, req);
            if (!from) continue;
            // `.length` / typeof comparisons are not content comparisons.
            if (memberName(ctx, strip(ctx, req)) === 'length' || t.isTypeOfExpression(strip(ctx, req))) continue;
            const why = secretSide(ctx, other);
            // Both sides from the request (and not a MAC computed over it): not a secret comparison.
            if (!why || (!why.startsWith('computed') && requestDerived(ctx, other))) continue;
            findings.push({
              node: n,
              message: `${from} is compared with a secret (${why}) using ${n.operatorToken.getText()}; the comparison time leaks how much of the guess is correct. Use crypto.timingSafeEqual().`,
              confidence: why.startsWith('computed') ? 'high' : 'medium',
              evidenceKind: 'pattern',
              evidence: [`request side: ${from}`, `secret side: ${why}`],
            });
            break;
          }
        }
        t.forEachChild(n, visit);
      };
      visit(sf);
    }
    return findings;
  },
});
