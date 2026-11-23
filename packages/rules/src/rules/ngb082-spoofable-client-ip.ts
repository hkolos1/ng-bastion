import type * as ts from 'typescript';
import { defineRule, type AnalysisContext, type RuleFinding } from '@ngbastion/plugin-api';
import { memberName, receiverOf, strip } from '../shared/common.js';
import { isServerRequest, requestHeaderRead } from '../shared/server.js';

const IP_HEADERS = ['x-forwarded-for', 'x-real-ip', 'true-client-ip', 'cf-connecting-ip', 'x-client-ip', 'x-cluster-client-ip', 'fastly-client-ip', 'forwarded'];
/** Literal that looks like an IPv4 / IPv6 address or prefix, or `localhost`. */
const IP_LITERAL = /['"`](\d{1,3}\.\d{1,3}\.|\d{1,3}\.$|::1|::ffff:|localhost|127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/;
const IP_HELPER = /\b(isPrivate|isLoopback|isLocal|inRange|ipRangeCheck|cidr\w*|isInSubnet|contains|matchCidr|range\w*)\s*\(/i;
const ALLOWLIST_NAME = /(allow|whitelist|trusted|admin|internal|office|vpn|blocked?|deny|banned|ip)/i;

/** Expression reading a client-supplied IP: forwarding headers, or `req.ip` / `req.ips` when `trust proxy` is `true`. */
function ipSource(ctx: AnalysisContext, e: ts.Expression, trustAll: boolean): string | undefined {
  const t = ctx.ts;
  let x = strip(ctx, e);
  // req.headers['x-forwarded-for'].split(',')[0].trim()
  for (let i = 0; i < 6; i++) {
    if (t.isCallExpression(x) && t.isPropertyAccessExpression(strip(ctx, x.expression)) && ['split', 'trim', 'toString', 'toLowerCase', 'shift', 'at', 'pop', 'replace'].includes(memberName(ctx, x.expression) ?? '')) x = strip(ctx, receiverOf(ctx, strip(ctx, x.expression))!);
    else if (t.isElementAccessExpression(x) && t.isNumericLiteral(x.argumentExpression)) x = strip(ctx, x.expression);
    else if (t.isBinaryExpression(x) && (x.operatorToken.kind === t.SyntaxKind.BarBarToken || x.operatorToken.kind === t.SyntaxKind.QuestionQuestionToken)) x = strip(ctx, x.left);
    else break;
  }
  const h = requestHeaderRead(ctx, x, IP_HEADERS);
  if (h) return `request header '${h}'`;
  if (trustAll && (t.isPropertyAccessExpression(x) || t.isElementAccessExpression(x))) {
    const m = memberName(ctx, x);
    if ((m === 'ip' || m === 'ips') && isServerRequest(ctx, x.expression)) return `req.${m} with trust proxy enabled for every hop`;
  }
  return undefined;
}

/** `app.set('trust proxy', true)` anywhere in the project. */
function trustsEveryProxy(ctx: AnalysisContext): ts.CallExpression | undefined {
  return ctx.index.calls.find((c) => memberName(ctx, c.expression) === 'set' && c.arguments.length === 2 && ctx.symbols.constantString(c.arguments[0]!) === 'trust proxy' && strip(ctx, c.arguments[1]!).kind === ctx.ts.SyntaxKind.TrueKeyword);
}

/** Whether a condition is an IP access-control check on `ref`. */
function accessCheck(ctx: AnalysisContext, cond: ts.Expression, mentions: (n: ts.Node) => boolean): boolean {
  const t = ctx.ts;
  let hit = false;
  const visit = (n: ts.Node): void => {
    if (hit) return;
    if (t.isBinaryExpression(n) && /^[!=]==?$/.test(n.operatorToken.getText()) && (mentions(n.left) || mentions(n.right)) && IP_LITERAL.test(n.getText())) hit = true;
    if (t.isCallExpression(n) && n.arguments.some((a) => mentions(a)) || t.isCallExpression(n) && mentions(n.expression)) {
      const text = n.expression.getText();
      if (IP_HELPER.test(`${text}(`) || (/\.(includes|has|indexOf|some|startsWith)$/.test(text) && (ALLOWLIST_NAME.test(text) || IP_LITERAL.test(n.getText())))) hit = true;
    }
    t.forEachChild(n, visit);
  };
  visit(cond);
  return hit;
}

export const ngb082 = defineRule({
  meta: {
    id: 'NGB082',
    name: 'Spoofable client IP used for access control',
    category: 'ssr',
    defaultSeverity: 'high',
    cwe: ['CWE-290', 'CWE-348'],
    docs: {
      description:
        "Reports server code that makes an access-control decision from a client IP taken from forwarding headers (`X-Forwarded-For`, `X-Real-IP`, `True-Client-IP`, `CF-Connecting-IP`, `X-Client-IP`, `Forwarded`) or from Express `req.ip` / `req.ips` while `app.set('trust proxy', true)` trusts every hop: comparisons with IP literals, allowlist / blocklist lookups and CIDR helpers in `if` / ternary / logical conditions.",
      rationale:
        "These headers are plain request headers: any client can send `X-Forwarded-For: 127.0.0.1`. Proxies append to the header rather than replace it, so the left-most value is always attacker-chosen, and `trust proxy: true` makes Express return exactly that value as `req.ip`. Admin endpoints, internal APIs or IP-based bypasses guarded this way are open to everyone.",
      patterns: [
        "Header reads: `req.headers['x-forwarded-for']`, `req.get('x-real-ip')`, `req.header('True-Client-IP')`, also after `.split(',')[0].trim()` / `|| fallback`, directly in the condition or through a local variable",
        "`req.ip` / `req.ips` when the project calls `app.set('trust proxy', true)`",
        "Decisions: `ip === '127.0.0.1'`, `ip.startsWith('10.')`, `ALLOWED_IPS.includes(ip)`, `blocked.has(ip)`, `ipRangeCheck(ip, …)`, `isPrivate(ip)` in an `if`, ternary or `&&` / `||` condition",
      ],
      limitations: [
        'Checks performed in helper functions that receive the IP as a parameter are not followed.',
        "Proxy-specific settings (a trusted hop count, `trust proxy: 'loopback'`) make `req.ip` reliable and are not reported; the proxy deployment itself is not visible.",
        'Rate limiting keyed by these headers (bypassable, but not an authorization decision) is not reported.',
      ],
      falsePositives: [
        'Code behind a proxy that strips and rewrites these headers (e.g. Cloudflare-only origins reading `CF-Connecting-IP` with origin firewalling) is not exploitable; document an exception naming that control.',
      ],
      remediation:
        "Do not authorize by IP from request headers. If IP checks are needed, configure Express `trust proxy` with the exact number of trusted hops or the proxy addresses and use `req.ip`, or use the socket address (`req.socket.remoteAddress`) when there is no proxy — and prefer real authentication for privileged endpoints.",
      example: {
        unsafe: "const ip = req.headers['x-forwarded-for']?.split(',')[0];\nif (ip !== '127.0.0.1') return res.sendStatus(403);",
        safe: "app.set('trust proxy', 1); // exactly one trusted reverse proxy\nif (!ADMIN_NETWORK.contains(req.ip)) return res.sendStatus(403);",
      },
      references: [
        { title: 'Express — behind proxies (trust proxy)', url: 'https://expressjs.com/en/guide/behind-proxies.html' },
        { title: 'MDN — X-Forwarded-For (security and privacy concerns)', url: 'https://developer.mozilla.org/docs/Web/HTTP/Headers/X-Forwarded-For#security_and_privacy_concerns' },
      ],
    },
  },
  analyze(ctx) {
    const t = ctx.ts;
    const findings: RuleFinding[] = [];
    const trustCall = trustsEveryProxy(ctx);
    const reported = new Set<ts.Node>();
    const conditionsIn = (scope: ts.Node): ts.Expression[] => {
      const out: ts.Expression[] = [];
      const visit = (n: ts.Node): void => {
        if (t.isIfStatement(n) || t.isConditionalExpression(n) || t.isWhileStatement(n)) out.push(t.isConditionalExpression(n) ? n.condition : n.expression);
        else if (t.isBinaryExpression(n) && (n.operatorToken.kind === t.SyntaxKind.AmpersandAmpersandToken || n.operatorToken.kind === t.SyntaxKind.BarBarToken) && !(t.isIfStatement(n.parent) || t.isConditionalExpression(n.parent))) out.push(n.left);
        else if (t.isReturnStatement(n) && n.expression) out.push(n.expression);
        t.forEachChild(n, visit);
      };
      visit(scope);
      return out;
    };
    const fns = new Set<ts.Node>();
    // Collect functions that read a spoofable IP.
    const visitReads = (n: ts.Node): void => {
      if (t.isExpression(n) && ipSource(ctx, n, !!trustCall)) fns.add(ctx.flow.enclosingFunction(n) ?? n.getSourceFile());
      t.forEachChild(n, visitReads);
    };
    for (const sf of ctx.sourceFiles) if (/x-forwarded|x-real-ip|true-client-ip|connecting-ip|client-ip|forwarded|\.ips?\b/i.test(sf.text)) visitReads(sf);
    for (const fn of fns) {
      // Local variables holding a spoofable IP.
      const vars = new Map<ts.Declaration, string>();
      const collect = (n: ts.Node): void => {
        if (t.isVariableDeclaration(n) && n.initializer && t.isIdentifier(n.name)) {
          const src = ipSource(ctx, n.initializer, !!trustCall);
          if (src) vars.set(n, src);
        }
        t.forEachChild(n, collect);
      };
      collect(fn);
      for (const cond of conditionsIn(fn)) {
        let source: string | undefined;
        const mentions = (n: ts.Node): boolean => {
          let hit = false;
          const v = (m: ts.Node): void => {
            if (hit) return;
            if (t.isExpression(m)) {
              const s = ipSource(ctx, m, !!trustCall);
              if (s) { source = s; hit = true; return; }
              if (t.isIdentifier(m)) {
                const d = ctx.symbols.declarationOf(m);
                if (d && vars.has(d)) { source = vars.get(d); hit = true; return; }
              }
            }
            t.forEachChild(m, v);
          };
          v(n);
          return hit;
        };
        if ([...reported].some((r) => r.getSourceFile() === cond.getSourceFile() && cond.pos >= r.pos && cond.end <= r.end) || !accessCheck(ctx, cond, mentions)) continue;
        reported.add(cond);
        findings.push({
          node: cond,
          message: `Access decision based on ${source}, which the client can set to any value (e.g. X-Forwarded-For: 127.0.0.1).`,
          confidence: source?.startsWith('req.') ? 'medium' : 'high',
          severity: source?.startsWith('req.') ? 'medium' : 'high',
          evidenceKind: 'pattern',
          evidence: [`client IP from ${source}`, ...(trustCall ? [`trust proxy: true at line ${ctx.location(trustCall).line}`] : [])],
        });
      }
    }
    return findings;
  },
});
