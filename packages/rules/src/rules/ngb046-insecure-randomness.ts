import type * as ts from 'typescript';
import { defineRule, type AnalysisContext, type Confidence, type RuleFinding } from '@ngbastion/plugin-api';
import { strip } from '../shared/common.js';
import { classifyName, words } from '../shared/sensitivity.js';

/** Words that mark a value as a security secret or protocol nonce (beyond the credential vocabulary). */
const SECURITY_WORDS = new Set(['nonce', 'state', 'csrf', 'xsrf', 'salt', 'iv', 'verifier', 'challenge', 'otp', 'totp', 'pin', 'secret', 'password', 'passphrase', 'captcha', 'invite', 'reset', 'signature']);
/** `stateKey`, `keyboard…` — words that make the security noun incidental. */
const NOT_SECURITY = new Set(['color', 'colour', 'theme', 'animation', 'delay', 'jitter', 'retry', 'backoff', 'index', 'position', 'offset', 'sample', 'shuffle', 'avatar', 'placeholder', 'demo', 'mock', 'test', 'track', 'trackby', 'element', 'dom', 'html', 'css', 'class', 'component', 'uuid', 'label', 'width', 'height', 'size', 'opacity', 'speed']);

const STORE_CALLS = new Set(['setItem', 'set', 'append']);

/** Name that labels the value: assignment target, variable, property, storage key, or the nearest named function. */
function labels(ctx: AnalysisContext, node: ts.Node): { name: string; via: 'value' | 'function' }[] {
  const t = ctx.ts;
  const out: { name: string; via: 'value' | 'function' }[] = [];
  let n: ts.Node = node;
  // Climb through expressions that turn the random number into a string/number value.
  for (;;) {
    const p = n.parent;
    if (!p) break;
    if (t.isCallExpression(p) && p.expression !== n && t.isPropertyAccessExpression(p.expression) && STORE_CALLS.has(p.expression.name.text)) {
      const k = p.arguments[0] && p.arguments[0] !== n ? ctx.symbols.constantString(p.arguments[0]) : undefined;
      if (k) out.push({ name: k, via: 'value' });
      break;
    }
    if (t.isBinaryExpression(p) && p.operatorToken.kind === t.SyntaxKind.EqualsToken) break;
    if (t.isBinaryExpression(p) || t.isCallExpression(p) || t.isPropertyAccessExpression(p) || t.isParenthesizedExpression(p) || t.isTemplateSpan(p)
      || t.isTemplateExpression(p) || t.isElementAccessExpression(p) || t.isArrayLiteralExpression(p) || (t.isArrowFunction(p) && p.body === n)) {
      n = p;
      continue;
    }
    break;
  }
  const p = n.parent;
  if (p && (t.isVariableDeclaration(p) || t.isPropertyDeclaration(p) || t.isPropertyAssignment(p)) && t.isIdentifier(p.name)) out.push({ name: p.name.text, via: 'value' });
  if (p && t.isBinaryExpression(p) && p.right === n) {
    const left = strip(ctx, p.left);
    const name = t.isPropertyAccessExpression(left) ? left.name.text : t.isIdentifier(left) ? left.text : undefined;
    if (name) out.push({ name, via: 'value' });
  }
  for (let fn = ctx.flow.enclosingFunction(node); fn; fn = ctx.flow.enclosingFunction(fn)) {
    const fnName = fn.name && t.isIdentifier(fn.name) ? fn.name.text
      : t.isVariableDeclaration(fn.parent) && t.isIdentifier(fn.parent.name) ? fn.parent.name.text
        : t.isPropertyAssignment(fn.parent) || t.isPropertyDeclaration(fn.parent) ? fn.parent.name.getText() : undefined;
    if (fnName) {
      out.push({ name: fnName, via: 'function' });
      break;
    }
  }
  return out;
}

function securityTerm(name: string): string | undefined {
  const w = words(name);
  if (w.some((x) => NOT_SECURITY.has(x))) return undefined;
  if (classifyName(name)?.category === 'credential') return name;
  return w.some((x) => SECURITY_WORDS.has(x)) ? name : undefined;
}

export const ngb046 = defineRule({
  meta: {
    id: 'NGB046',
    name: 'Insecure randomness for security values',
    category: 'cryptography',
    defaultSeverity: 'high',
    cwe: ['CWE-338', 'CWE-330'],
    docs: {
      description:
        "Reports `Math.random()` used to produce security-sensitive values: the result is stored in, or returned by a function named like, a token, password, secret, key, session ID, OAuth `state` / `nonce`, PKCE verifier, CSRF token, salt, IV, OTP or reset / invite code.",
      rationale:
        "`Math.random()` is not a cryptographic generator: V8 uses xorshift128+, whose internal state can be recovered from a handful of outputs, after which every past and future value is predictable. Tokens, OAuth `state`, nonces and reset codes built from it can be guessed. `crypto.getRandomValues()` and `crypto.randomUUID()` are available in every supported browser and in Node.js.",
      patterns: [
        '`Math.random()` (global, symbol-resolved) flowing — through arithmetic, `toString(36)`, `substring`, `Math.floor`, template literals, array index lookups — into a variable, property, storage key or object property',
        'Security names: credential vocabulary of NGB014/NGB016 plus `nonce`, `state`, `csrf`, `salt`, `iv`, `verifier`, `challenge`, `otp`, `pin`, `secret`, `captcha`, `invite`, `reset`, `signature`',
        'The enclosing function name counts as well (`generateToken()`, `createNonce()`, `randomPassword()`) with medium confidence',
        'Names about UI or test data (`color`, `delay`, `jitter`, `shuffle`, `trackById`, `mock`, `id`, `uuid`) are ignored',
      ],
      limitations: [
        'Random values passed to other functions before being named are only classified by the enclosing function name.',
        'Third-party random libraries (e.g. `nanoid/non-secure`, `random-js` with a Math.random engine) are not recognized.',
      ],
      falsePositives: [
        'Non-security identifiers that use security words (e.g. a UI `stateKey` for animations) can be reported; rename or document.',
      ],
      remediation:
        "Use `crypto.getRandomValues(new Uint8Array(32))` (encode as base64url / hex) or `crypto.randomUUID()` for identifiers. In Node.js SSR code use `crypto.randomBytes()`.",
      example: {
        unsafe: `const state = Math.random().toString(36).substring(2);`,
        safe: `const state = btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(32))));`,
      },
      references: [
        { title: 'OWASP — Cryptographic Storage: secure random numbers', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html#secure-random-number-generation' },
        { title: 'MDN — Crypto.getRandomValues()', url: 'https://developer.mozilla.org/docs/Web/API/Crypto/getRandomValues' },
      ],
    },
  },
  analyze(ctx) {
    const findings: RuleFinding[] = [];
    const seen = new Set<string>();
    for (const call of ctx.index.calls) {
      const info = ctx.symbols.callee(call);
      if (!info || info.name !== 'random' || info.declaration || strip(ctx, call.expression).getText() !== 'Math.random') continue;
      if (info.receiver && info.receiver.module !== 'lib') continue;
      let hit: { term: string; confidence: Confidence } | undefined;
      for (const l of labels(ctx, call)) {
        const term = securityTerm(l.name);
        if (term) {
          hit = { term, confidence: l.via === 'value' ? 'high' : 'medium' };
          break;
        }
      }
      if (!hit) continue;
      const key = `${call.getSourceFile().fileName}:${hit.term}:${ctx.flow.enclosingFunction(call)?.pos ?? 0}`;
      if (seen.has(key)) continue;
      seen.add(key);
      findings.push({
        node: call,
        message: `Math.random() generates '${hit.term}'; its output is predictable. Use crypto.getRandomValues() for security values.`,
        confidence: hit.confidence,
        evidenceKind: 'heuristic',
        evidence: [`security-relevant name: ${hit.term}`],
      });
    }
    return findings;
  },
});
