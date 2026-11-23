import { defineRule, type Confidence, type RuleFinding } from '@ngbastion/plugin-api';
import { is, relative } from '../shared/common.js';
import { authSignals } from '../shared/auth.js';
import { HTTP_MODULE } from '../shared/http.js';

export const ngb021 = defineRule({
  meta: {
    id: 'NGB021',
    name: 'Disabled XSRF protection',
    category: 'navigation-auth',
    defaultSeverity: 'high',
    cwe: ['CWE-352'],
    docs: {
      description:
        "Reports code that turns off Angular's built-in XSRF (CSRF) protection: `withNoXsrfProtection()` in `provideHttpClient(...)` and `HttpClientXsrfModule.disable()`. Confidence depends on how the application authenticates: high when the project sends cookies with requests (`withCredentials: true`, `credentials: 'include'`), low when it authenticates with `Authorization` headers only, medium when neither is visible.",
      rationale:
        "With cookie-based sessions the browser attaches the session cookie to any request to your API, including ones triggered by other sites. Angular's `HttpXsrfInterceptor` copies the `XSRF-TOKEN` cookie into an `X-XSRF-TOKEN` header for mutating same-origin requests, which a cross-site attacker cannot do. Disabling it removes the client half of that defence; the server must then rely solely on SameSite cookies or other checks.",
      patterns: [
        '`provideHttpClient(withNoXsrfProtection())` (function from `@angular/common/http`)',
        '`HttpClientXsrfModule.disable()` in NgModule imports',
        'Cookie-auth evidence: `withCredentials: true` or `credentials: "include"` anywhere in the project (raises confidence)',
        'Bearer-auth evidence: `Authorization` headers attached in code (lowers confidence: header-authenticated APIs are not CSRF-prone)',
      ],
      limitations: [
        'The server side is not visible: whether the backend validates the XSRF header, uses SameSite cookies or other CSRF defences cannot be assessed.',
        "Angular only adds the XSRF header to mutating requests to relative / same-origin URLs; disabling it has no effect on cross-origin APIs, which need server-side CSRF protection anyway.",
        'Custom `HttpXsrfTokenExtractor` providers that return no token are not detected.',
      ],
      falsePositives: [
        'Applications that authenticate exclusively with bearer tokens in headers do not need XSRF tokens; such findings are low confidence.',
      ],
      remediation:
        "Remove `withNoXsrfProtection()` / `HttpClientXsrfModule.disable()`. If your backend uses different names, configure them with `withXsrfConfiguration({ cookieName: '…', headerName: '…' })` and make the server reject mutating requests without a matching token.",
      example: {
        unsafe: `provideHttpClient(withInterceptors([auth]), withNoXsrfProtection())`,
        safe: `provideHttpClient(withInterceptors([auth]), withXsrfConfiguration({ cookieName: 'XSRF-TOKEN', headerName: 'X-XSRF-TOKEN' }))`,
      },
      references: [
        { title: 'Angular — HttpClient XSRF/CSRF security', url: 'https://angular.dev/best-practices/security#httpclient-xsrf-csrf-security' },
        { title: 'OWASP — CSRF Prevention Cheat Sheet', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html' },
      ],
    },
  },
  analyze(ctx) {
    const findings: RuleFinding[] = [];
    for (const call of ctx.index.calls) {
      const info = ctx.symbols.callee(call);
      if (!info || info.declaration) continue;
      let what: string | undefined;
      if (info.name === 'withNoXsrfProtection' && is(info.origin, HTTP_MODULE)) what = 'withNoXsrfProtection()';
      else if (info.name === 'disable' && is(info.receiver, HTTP_MODULE, 'HttpClientXsrfModule')) what = 'HttpClientXsrfModule.disable()';
      if (!what) continue;
      const signals = authSignals(ctx);
      const where = (n: { getSourceFile(): { fileName: string } }) => relative(ctx, n.getSourceFile().fileName);
      let confidence: Confidence = 'medium';
      const evidence = [`${what} disables Angular's XSRF header interceptor`];
      if (signals.cookieCredentials.length) {
        confidence = 'high';
        evidence.push(`cookies are sent with requests (${where(signals.cookieCredentials[0]!)}:${ctx.location(signals.cookieCredentials[0]!).line})`);
      } else if (signals.bearerHeaders.length) {
        confidence = 'low';
        evidence.push(`requests carry an Authorization header (${where(signals.bearerHeaders[0]!)}:${ctx.location(signals.bearerHeaders[0]!).line}); header-authenticated APIs are not CSRF-prone`);
      } else {
        evidence.push('authentication mechanism not visible in code');
      }
      findings.push({
        node: call,
        message: `${what} turns off Angular's XSRF protection; with cookie-based authentication, other sites can submit state-changing requests on behalf of signed-in users.`,
        confidence,
        evidenceKind: 'pattern',
        evidence,
      });
    }
    return findings;
  },
});
