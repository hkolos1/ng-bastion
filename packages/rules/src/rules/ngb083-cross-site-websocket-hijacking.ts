import type * as ts from 'typescript';
import { defineRule, type AnalysisContext, type RuleFinding } from '@ngbastion/plugin-api';
import { memberName, receiverOf, strip } from '../shared/common.js';
import { objectLiteral, objectProp } from '../shared/http.js';
import { moduleCall } from '../shared/server.js';

/** Handler code that authenticates the connection with ambient browser credentials. */
const COOKIE_AUTH = /\.headers\s*(\.cookie\b|\[\s*['"`]cookie['"`]\s*\])|\b(req|request)\.(session|cookies|signedCookies)\b|\bsession(Parser|Middleware)\b|\bcookie\.parse\b|\bparseCookies?\b|\bpassport\b/i;
const ORIGIN_CHECK = /\.headers\s*(\.origin\b|\[\s*['"`]origin['"`]\s*\])|\borigin\b/i;

interface WsServer {
  node: ts.NewExpression;
  lib: 'ws' | 'socket.io';
  options?: ts.ObjectLiteralExpression;
  decl?: ts.Declaration;
}

function declOf(ctx: AnalysisContext, n: ts.Node): ts.Declaration | undefined {
  const t = ctx.ts;
  let x: ts.Node = n;
  while (x.parent && (t.isParenthesizedExpression(x.parent) || t.isAsExpression(x.parent))) x = x.parent;
  return x.parent && t.isVariableDeclaration(x.parent) && x.parent.initializer === x ? x.parent : undefined;
}

/** `x.on(event, fn)` / `x.use(fn)` / `x.engine.use(fn)` handlers registered on a server variable. */
function handlers(ctx: AnalysisContext, server: WsServer): ts.Node[] {
  const t = ctx.ts;
  const out: ts.Node[] = [];
  for (const call of ctx.index.calls) {
    const m = memberName(ctx, call.expression);
    if (!m || !['on', 'use', 'once'].includes(m)) continue;
    let recv = receiverOf(ctx, strip(ctx, call.expression));
    if (recv && memberName(ctx, strip(ctx, recv)) === 'engine') recv = receiverOf(ctx, strip(ctx, recv));
    const r = recv && strip(ctx, recv);
    const event = m === 'use' ? undefined : call.arguments[0] && ctx.symbols.constantString(call.arguments[0]);
    const fnArg = call.arguments[m === 'use' ? 0 : 1];
    if (!fnArg) continue;
    const onServer = !!r && (r === server.node || (!!server.decl && t.isIdentifier(r) && ctx.symbols.declarationOf(r) === server.decl));
    // HTTP server 'upgrade' handlers in the same file feed `noServer` WebSocket servers.
    const upgrade = event === 'upgrade' && call.getSourceFile() === server.node.getSourceFile();
    if ((onServer && (m === 'use' || event === 'connection' || event === 'headers')) || upgrade) out.push(ctx.flow.resolveFunction(fnArg) ?? fnArg);
  }
  return out;
}

export const ngb083 = defineRule({
  meta: {
    id: 'NGB083',
    name: 'Cross-site WebSocket hijacking',
    category: 'ssr',
    defaultSeverity: 'high',
    cwe: ['CWE-1385', 'CWE-346'],
    docs: {
      description:
        "Reports WebSocket servers that authenticate connections with cookies or the HTTP session but never check the handshake's `Origin`: `ws` `WebSocketServer` without `verifyClient` whose `connection` / `upgrade` handlers read cookies or the session, Socket.IO servers that use cookie / session middleware without `allowRequest`, and Socket.IO `cors: { origin: true | '*', credentials: true }`.",
      rationale:
        "The WebSocket handshake is not protected by the same-origin policy or CORS: any website can open `new WebSocket('wss://your-app/ws')` and the browser attaches the victim's cookies. If the server trusts those cookies and does not verify the `Origin` header, the attacker's page gets a fully authenticated, bidirectional channel — reading private messages and sending commands as the user (cross-site WebSocket hijacking).",
      patterns: [
        "`new WebSocketServer({ … })` / `new WebSocket.Server({ … })` from `ws` without `verifyClient`, whose `wss.on('connection', (ws, req) => …)` or same-file `server.on('upgrade', …)` handler reads `req.headers.cookie`, `req.session`, `req.cookies`, a session parser or `cookie.parse`, and never mentions the origin",
        "`new Server(httpServer, { … })` from `socket.io` without `allowRequest`, with `io.use(…)` / `io.engine.use(…)` / `io.on('connection', …)` handlers that use cookies or the session (medium confidence)",
        "Socket.IO `cors: { origin: true | '*' | (o, cb) => cb(null, true), credentials: true }` (high)",
      ],
      limitations: [
        'Origin checks inside helper functions called from the handler are not seen; mentioning `origin` anywhere in the handler counts as a check.',
        "Socket.IO servers created with the call form (`require('socket.io')(server)`) and other WebSocket libraries (uWebSockets.js, SockJS) are not analyzed.",
        'Token-based authentication sent in the first message is safe and not reported; tokens in cookies are treated as cookie authentication.',
      ],
      falsePositives: [
        'Servers reachable only from a private network are reported; the network boundary is not visible.',
      ],
      remediation:
        "Verify the `Origin` header against an allowlist during the handshake (`verifyClient` for `ws`, `allowRequest` for Socket.IO) before trusting cookies, or authenticate WebSocket connections with a short-lived token that a cross-site page cannot read.",
      example: {
        unsafe: "const wss = new WebSocketServer({ server });\nwss.on('connection', (ws, req) => {\n  const user = sessions.get(cookie.parse(req.headers.cookie ?? '').sid);\n  ws.on('message', (m) => handle(user, m));\n});",
        safe: "const wss = new WebSocketServer({\n  server,\n  verifyClient: ({ origin }) => ALLOWED_ORIGINS.includes(origin),\n});",
      },
      references: [
        { title: 'PortSwigger — Cross-site WebSocket hijacking', url: 'https://portswigger.net/web-security/websockets/cross-site-websocket-hijacking' },
        { title: 'OWASP — WebSocket Security Cheat Sheet', url: 'https://cheatsheetseries.owasp.org/cheatsheets/WebSocket_Security_Cheat_Sheet.html' },
      ],
    },
  },
  analyze(ctx) {
    const t = ctx.ts;
    const findings: RuleFinding[] = [];
    const servers: WsServer[] = [];
    for (const ne of ctx.index.newExpressions) {
      if (moduleCall(ctx, ne, ['ws'], ['WebSocketServer', 'Server'])) {
        const options = objectLiteral(ctx, ne.arguments?.[0]);
        servers.push({ node: ne, lib: 'ws', ...(options ? { options } : {}), ...(declOf(ctx, ne) ? { decl: declOf(ctx, ne)! } : {}) });
      } else if (moduleCall(ctx, ne, ['socket.io'], ['Server'])) {
        const options = objectLiteral(ctx, ne.arguments?.[1]) ?? objectLiteral(ctx, ne.arguments?.[0]);
        servers.push({ node: ne, lib: 'socket.io', ...(options ? { options } : {}), ...(declOf(ctx, ne) ? { decl: declOf(ctx, ne)! } : {}) });
      }
    }
    for (const s of servers) {
      if (s.lib === 'socket.io') {
        const cors = objectLiteral(ctx, objectProp(ctx, s.options, 'cors'));
        const cred = objectProp(ctx, cors, 'credentials');
        const origin = objectProp(ctx, cors, 'origin');
        if (cred && strip(ctx, cred).kind === t.SyntaxKind.TrueKeyword && origin) {
          const o = strip(ctx, origin);
          const any = o.kind === t.SyntaxKind.TrueKeyword || ctx.symbols.constantString(o) === '*' || ((t.isArrowFunction(o) || t.isFunctionExpression(o)) && /\(\s*null\s*,\s*true\s*\)/.test(o.getText()) && !/\.(includes|has|test)\(|===|if\s*\(/.test(o.getText()));
          if (any) {
            findings.push({ node: s.node, message: 'Socket.IO allows credentialed connections from any origin (cors.origin allows all with credentials: true); any website can open an authenticated session with the user\'s cookies.', confidence: 'high', evidenceKind: 'pattern', evidence: [`cors.origin: ${o.getText().slice(0, 60)}`, 'cors.credentials: true'] });
            continue;
          }
        }
      }
      const verified = s.lib === 'ws' ? objectProp(ctx, s.options, 'verifyClient') : objectProp(ctx, s.options, 'allowRequest');
      if (verified) continue;
      const hs = handlers(ctx, s);
      const authBy = hs.find((h) => COOKIE_AUTH.test(h.getText()));
      if (!authBy || hs.some((h) => ORIGIN_CHECK.test(h.getText()))) continue;
      findings.push({
        node: s.node,
        message: `${s.lib === 'ws' ? 'WebSocket server' : 'Socket.IO server'} authenticates connections with cookies / the session but never checks the handshake Origin; any website can open an authenticated connection as the visiting user.`,
        confidence: s.lib === 'ws' ? 'high' : 'medium',
        evidenceKind: 'pattern',
        evidence: [`cookie/session use in handler at line ${ctx.location(authBy).line}`, s.lib === 'ws' ? 'no verifyClient option' : 'no allowRequest option', 'no Origin check in connection / upgrade handlers'],
      });
    }
    return findings;
  },
});
