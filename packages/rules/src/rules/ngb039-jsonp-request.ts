import { defineRule, type RuleFinding } from '@ngbastion/plugin-api';
import { constantPrefix, flowEvidence, hasFixedOrigin, is, sinkStep } from '../shared/common.js';
import { HTTP_MODULE } from '../shared/http.js';

export const ngb039 = defineRule({
  meta: {
    id: 'NGB039',
    name: 'JSONP request',
    category: 'angular-xss',
    defaultSeverity: 'medium',
    cwe: ['CWE-829', 'CWE-95'],
    docs: {
      description:
        "Reports `HttpClient.jsonp()` requests. JSONP loads the response as a `<script>`, so the remote server executes code in your application's origin. Severity: high when the URL is traced to an attacker-controllable source, medium for fixed third-party URLs, low (low confidence) for same-origin relative URLs.",
      rationale:
        "With JSONP there is no data boundary: whatever the endpoint returns runs with full access to your page, tokens and DOM. A compromised or malicious JSONP provider, a callback-parameter injection on the provider, or an attacker-chosen URL is immediate script execution (XSS) that CSP `connect-src` does not restrict. CORS made JSONP unnecessary.",
      patterns: [
        '`http.jsonp(url, callbackParam)` on `HttpClient` from `@angular/common/http`',
        'URL traced to ActivatedRoute / `location` values, postMessage data, `window.name`, referrer → high',
        'Constant `https://other.host/…` → medium; relative same-origin URL → low',
      ],
      limitations: [
        'Hand-written JSONP (creating `<script src="…?callback=…">`) is covered by NGB005, not this rule.',
        '`withJsonpSupport()` / `HttpClientJsonpModule` registrations without visible `jsonp()` calls are not reported.',
      ],
      falsePositives: [
        'Legacy first-party JSONP endpoints on the same origin are reported with low confidence.',
      ],
      remediation:
        "Replace JSONP with `HttpClient.get()` against an endpoint that sends CORS headers, then remove `withJsonpSupport()` / `HttpClientJsonpModule`. If a provider only offers JSONP, proxy it through your backend.",
      example: {
        unsafe: `this.http.jsonp('https://api.weather.example/v1/today', 'callback').subscribe(...)`,
        safe: `this.http.get('/api/weather/today').subscribe(...) // backend proxies the provider`,
      },
      references: [
        { title: 'Angular — HttpClient JSONP (withJsonpSupport)', url: 'https://angular.dev/api/common/http/withJsonpSupport' },
        { title: 'OWASP — Third-party JavaScript management', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Third_Party_Javascript_Management_Cheat_Sheet.html' },
      ],
    },
  },
  analyze(ctx) {
    const findings: RuleFinding[] = [];
    for (const call of ctx.index.calls) {
      const info = ctx.symbols.callee(call);
      if (!info || info.declaration || info.name !== 'jsonp' || !is(info.receiver, HTTP_MODULE, 'HttpClient') || !call.arguments[0]) continue;
      const url = call.arguments[0];
      const result = ctx.taint.trace(url, { context: 'resource-url' });
      const flow = result.flows.find((f) => ['url', 'message', 'window-name', 'referrer'].includes(f.source.kind));
      if (flow) {
        findings.push({
          node: call,
          message: `HttpClient.jsonp() loads a script from a URL controlled by ${flow.source.description}; the response executes as code in this origin (XSS).`,
          confidence: flow.confidence,
          severity: 'high',
          evidenceKind: 'dataflow',
          trace: [...flow.steps, sinkStep(ctx, call, 'HttpClient.jsonp() URL')],
          evidence: flowEvidence(flow),
        });
        continue;
      }
      const prefix = constantPrefix(ctx, url);
      const external = hasFixedOrigin(prefix) || /^\s*(https?:)?\/\//i.test(prefix ?? '');
      findings.push({
        node: call,
        message: external
          ? `HttpClient.jsonp() executes the response of ${prefix} as script in this origin; the provider (or anyone who compromises it) can run arbitrary code in your application.`
          : 'HttpClient.jsonp() executes the response as script; use HttpClient.get() with CORS instead.',
        confidence: external ? 'high' : 'low',
        severity: external ? 'medium' : 'low',
        evidenceKind: 'pattern',
        evidence: [`URL prefix: ${prefix ?? '(dynamic, origin unknown)'}`],
      });
    }
    return findings;
  },
});
