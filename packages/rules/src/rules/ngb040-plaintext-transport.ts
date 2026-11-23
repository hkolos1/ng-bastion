import type * as ts from 'typescript';
import { defineRule, type RuleFinding } from '@ngbastion/plugin-api';
import { constantPrefix, relative } from '../shared/common.js';
import { isPlaintextRemote, requestCalls } from '../shared/http.js';
import { sensitiveValue } from '../shared/sensitivity.js';

/** Production-like environment files (not `environment.development.ts` / `.local` / `.dev`). */
const PROD_ENV = /(^|[/\\])environments?[/\\]environment(\.prod(uction)?)?\.ts$/;
const URL_KEY = /(url|uri|endpoint|host|base|api|server|socket|ws)$/i;

export const ngb040 = defineRule({
  meta: {
    id: 'NGB040',
    name: 'Plaintext network transport',
    category: 'sensitive-data',
    defaultSeverity: 'medium',
    cwe: ['CWE-319'],
    docs: {
      description:
        "Reports network connections to non-local hosts over unencrypted protocols: `http://` URLs in `HttpClient`, `fetch()`, `XMLHttpRequest`, `navigator.sendBeacon()` and `EventSource`, `ws://` URLs in `WebSocket` / RxJS `webSocket()`, and `http://` / `ws://` API URLs in production environment files. Requests that carry credentials, an `Authorization` header or a sensitive body are high severity.",
      rationale:
        "From an HTTPS page browsers block such requests as mixed content, so in a correctly served app they simply fail — when they work, it is because the app itself runs over HTTP, the code executes during SSR in Node.js, or inside a hybrid shell. In all of those cases tokens, cookies and personal data cross the network unencrypted and can be read or modified by anyone on the path.",
      patterns: [
        'Requests (see NGB026) whose URL has a constant `http://host` / `ws://host` prefix',
        '`environment.ts` / `environment.prod.ts` / `environment.production.ts`: string properties named `*Url`, `*Uri`, `*Endpoint`, `*Host`, `api`, `socket`, … with `http://` / `ws://` values',
        'Local hosts are ignored: `localhost`, `127.x`, `0.0.0.0`, `[::1]`, `*.localhost`, `*.local`, `host.docker.internal`, private 10.x / 192.168.x addresses',
        'High severity with `withCredentials`, `credentials: "include"`, an `Authorization` header, a WebSocket (cookies are sent on the handshake) or a body classified as credential/payment data',
      ],
      limitations: [
        'URLs assembled from configuration that is not a constant (`environment.apiUrl` with a non-constant value, runtime config files) are only covered through the environment-file check.',
        'The serving protocol of the application itself (HTTP vs HTTPS, HSTS) is not visible.',
      ],
      falsePositives: [
        'Internal hostnames that are only reachable on a trusted network (e.g. `http://intranet-api`) are reported; they still travel unencrypted.',
      ],
      remediation:
        "Use `https://` and `wss://` for every non-local endpoint, serve the application over HTTPS with HSTS, and keep plain-HTTP URLs only in development environment files.",
      example: {
        unsafe: `const socket = new WebSocket('ws://realtime.example.com/feed');
this.http.post('http://api.example.com/login', { username, password });`,
        safe: `const socket = new WebSocket('wss://realtime.example.com/feed');
this.http.post('https://api.example.com/login', { username, password });`,
      },
      references: [
        { title: 'OWASP — Transport Layer Security Cheat Sheet', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html' },
        { title: 'MDN — Mixed content', url: 'https://developer.mozilla.org/docs/Web/Security/Mixed_content' },
      ],
    },
  },
  analyze(ctx) {
    const t = ctx.ts;
    const findings: RuleFinding[] = [];
    for (const r of requestCalls(ctx)) {
      const prefix = constantPrefix(ctx, r.url);
      if (!prefix) continue;
      const scheme = r.transport === 'websocket' ? 'ws' : 'http';
      if (!isPlaintextRemote(prefix, scheme)) continue;
      const body = r.body ? sensitiveValue(ctx, r.body) : undefined;
      const carries = [...(r.authHeader ? ['an Authorization header'] : []), ...(r.credentials && r.transport !== 'beacon' ? ['cookies'] : []), ...(body ? ['sensitive data'] : [])];
      findings.push({
        node: r.node,
        message: `${r.api} connects to ${prefix.match(/^\s*\w+:\/\/[^/?#]*/)![0]} without TLS${carries.length ? `, sending ${carries.join(' and ')}` : ''}; traffic can be read and modified on the network.`,
        confidence: 'high',
        severity: carries.length ? 'high' : 'medium',
        evidenceKind: 'pattern',
        evidence: [`URL prefix: ${prefix}`, ...(body?.evidence ?? [])],
      });
    }
    for (const sf of ctx.sourceFiles) {
      if (!PROD_ENV.test(sf.fileName)) continue;
      const visit = (n: ts.Node): void => {
        if (t.isPropertyAssignment(n) && (t.isIdentifier(n.name) || t.isStringLiteralLike(n.name)) && URL_KEY.test(n.name.text)) {
          const v = ctx.symbols.constantString(n.initializer);
          if (v && (isPlaintextRemote(v, 'http') || isPlaintextRemote(v, 'ws'))) {
            findings.push({
              node: n,
              message: `Environment setting '${n.name.text}' in ${relative(ctx, sf.fileName)} points to ${v.match(/^\s*\w+:\/\/[^/?#]*/)![0]} without TLS.`,
              confidence: 'medium',
              evidenceKind: 'pattern',
              evidence: [`${n.name.text}: ${v}`, 'production-like environment file'],
            });
          }
        }
        t.forEachChild(n, visit);
      };
      visit(sf);
    }
    return findings;
  },
});
