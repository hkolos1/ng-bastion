import type * as ts from 'typescript';
import { defineRule, type AnalysisContext, type RuleFinding } from '@ngbastion/plugin-api';
import { receiverOf, strip } from '../shared/common.js';
import { directNames, personalDataName, sensitiveValue } from '../shared/sensitivity.js';

interface AnalyticsSink {
  label: string;
  /** `event`: event / page payloads; `identity`: user identification APIs (PII there is by design). */
  kind: 'event' | 'identity';
  /** Credential / payment data in this sink is already reported by NGB016. */
  coveredByNgb016: boolean;
}

/** SDK → receiver names, module prefixes, event methods, identity methods. */
const SDKS: { name: string; receivers: RegExp; modules: RegExp; event: string[]; identity: string[] }[] = [
  { name: 'Segment', receivers: /^(window\.)?analytics$/, modules: /^@segment\//, event: ['track', 'page', 'screen'], identity: ['identify', 'group', 'alias'] },
  { name: 'Mixpanel', receivers: /^(window\.)?mixpanel(\.people)?$/, modules: /^mixpanel/, event: ['track', 'track_links', 'register', 'register_once'], identity: ['identify', 'set', 'set_once', 'alias'] },
  { name: 'Amplitude', receivers: /^(window\.)?amplitude(\.getInstance\(\))?$/, modules: /^@amplitude\/|^amplitude-js$/, event: ['track', 'logEvent'], identity: ['setUserId', 'identify', 'setUserProperties'] },
  { name: 'PostHog', receivers: /^(window\.)?posthog$/, modules: /^posthog-js/, event: ['capture', 'register'], identity: ['identify', 'alias', 'setPersonProperties'] },
  { name: 'Heap', receivers: /^(window\.)?heap$/, modules: /^@heap\//, event: ['track', 'addEventProperties'], identity: ['identify', 'addUserProperties'] },
  { name: 'LogRocket', receivers: /^LogRocket$/, modules: /^logrocket$/, event: ['track', 'log', 'info'], identity: ['identify'] },
  { name: 'FullStory', receivers: /^(window\.)?FS$/, modules: /^@fullstory\//, event: ['event', 'log'], identity: ['identify', 'setUserVars'] },
  { name: 'Datadog RUM', receivers: /^datadogRum$/, modules: /^@datadog\/browser-rum/, event: ['addAction', 'addError', 'setGlobalContextProperty'], identity: ['setUser', 'setUserProperty'] },
  { name: 'New Relic', receivers: /^(window\.)?newrelic$/, modules: /^@newrelic\//, event: ['addPageAction', 'setCustomAttribute', 'noticeError'], identity: ['setUserId'] },
  { name: 'Application Insights', receivers: /appInsights$/i, modules: /^@microsoft\/applicationinsights/, event: ['trackEvent', 'trackPageView', 'trackTrace'], identity: ['setAuthenticatedUserContext'] },
];

function sinkOf(ctx: AnalysisContext, call: ts.CallExpression): AnalyticsSink | undefined {
  const t = ctx.ts;
  const callee = strip(ctx, call.expression);
  const info = ctx.symbols.callee(call);
  // Ambient declarations (`declare function gtag(…)`) describe the SDK global; implemented project functions do not.
  const decl = info?.declaration as ts.FunctionLikeDeclaration | undefined;
  if (decl && decl.body) return undefined;
  if (t.isIdentifier(callee)) {
    if (callee.text === 'gtag') return { label: 'gtag()', kind: 'event', coveredByNgb016: true };
    if (callee.text === 'hj' || callee.text === 'clarity') return { label: `${callee.text}()`, kind: 'event', coveredByNgb016: false };
    // Named imports: track() from @amplitude/analytics-browser
    const mod = info?.origin?.module;
    for (const sdk of SDKS) {
      if (mod && sdk.modules.test(mod)) {
        if (sdk.event.includes(callee.text)) return { label: `${sdk.name} ${callee.text}()`, kind: 'event', coveredByNgb016: false };
        if (sdk.identity.includes(callee.text)) return { label: `${sdk.name} ${callee.text}()`, kind: 'identity', coveredByNgb016: false };
      }
    }
    return undefined;
  }
  const recv = receiverOf(ctx, callee);
  if (!recv || !t.isPropertyAccessExpression(callee)) return undefined;
  const method = callee.name.text;
  const recvText = strip(ctx, recv).getText().replace(/\s+/g, '');
  const mod = ctx.symbols.typeOrigin(recv)?.module ?? '';
  if (method === 'push' && /(^|\.)dataLayer$/.test(recvText)) return { label: 'dataLayer.push()', kind: 'event', coveredByNgb016: true };
  for (const sdk of SDKS) {
    if (!sdk.receivers.test(recvText) && !sdk.modules.test(mod)) continue;
    const covered = (sdk.name === 'PostHog' && method === 'capture') || (sdk.name === 'Datadog RUM' && method === 'addAction') || (sdk.name === 'Application Insights' && /^track(Event|Trace)$/.test(method));
    if (sdk.event.includes(method)) return { label: `${sdk.name} ${method}()`, kind: 'event', coveredByNgb016: covered };
    if (sdk.identity.includes(method)) return { label: `${sdk.name} ${method}()`, kind: 'identity', coveredByNgb016: covered };
  }
  return undefined;
}

export const ngb067 = defineRule({
  meta: {
    id: 'NGB067',
    name: 'Sensitive data sent to analytics',
    category: 'sensitive-data',
    defaultSeverity: 'medium',
    cwe: ['CWE-359', 'CWE-201'],
    docs: {
      description:
        "Reports sensitive values passed to product-analytics and session-replay SDKs: credentials and payment data sent to Segment, Mixpanel, Amplitude, PostHog (`identify` / `register`), Heap, LogRocket, FullStory, Datadog RUM (`setUser`), New Relic, Hotjar / Clarity (medium severity), and personal data — e-mail addresses, phone numbers, dates of birth, national IDs, IBANs — placed in event payloads of those SDKs, Google Analytics `gtag()` / `dataLayer.push()` and Application Insights `trackEvent()` (low severity). Credentials in `gtag`, `dataLayer`, Sentry, PostHog `capture`, Datadog `addAction` and Application Insights events are reported by NGB016 and not repeated here.",
      rationale:
        "Analytics events are copied to third-party processors, retained for years, exported to warehouses and visible to marketing staff — none of which are cleared to hold passwords, tokens or card data. Personal data in event properties breaks most analytics terms (Google Analytics forbids PII), creates GDPR / CCPA processing you did not declare, and cannot be selectively deleted afterwards. User-identification APIs (`identify`, `setUser`) exist for user IDs and traits; personal data there is a policy decision and is not reported.",
      patterns: [
        '`analytics.track/page/identify()` (Segment), `mixpanel.track/identify/register()` / `mixpanel.people.set()`, `amplitude.track/logEvent/setUserId()` and named imports from `@amplitude/*`, `posthog.capture/identify/register()`, `heap.track/identify()`, `LogRocket.identify/track()`, `FS.identify/event()`, `datadogRum.setUser/addAction()`, `newrelic.addPageAction/setCustomAttribute()`, `appInsights.trackEvent()`, `gtag()`, `dataLayer.push()`, `hj()`, `clarity()`',
        'Credentials / payment data: value name, type properties, names along the data flow (shared sensitivity model of NGB014–NGB016)',
        'Personal data: names such as `email`, `phoneNumber`, `dateOfBirth`, `ssn`, `iban`, `passportNumber` on the value or the keys of an inline payload object',
      ],
      limitations: [
        'SDKs wrapped in a project analytics service are only recognized at the SDK call, not at the wrapper.',
        'Automatic collection (URL capture, autocapture of input fields, session replay recordings) is configured in the SDK and is not analyzed.',
      ],
      falsePositives: [
        'Hashed or pseudonymized identifiers named `email` are reported unless the expression visibly hashes or masks them.',
        'Self-hosted analytics with a data-processing agreement covering personal data may accept e-mail addresses; document an exception.',
      ],
      remediation:
        'Send opaque, stable user IDs and coarse attributes (plan, country) instead of personal data; never send tokens, passwords or card data. Strip query strings with tokens before page tracking and enable the SDK\'s input masking / PII redaction options.',
      example: {
        unsafe: `analytics.track('Signed Up', { email: form.email, password: form.password });`,
        safe: `analytics.track('Signed Up', { plan: form.plan }); // identify(userId) with an opaque ID`,
      },
      references: [
        { title: 'Google Analytics — Best practices to avoid sending PII', url: 'https://support.google.com/analytics/answer/6366371' },
        { title: 'OWASP Top 10 Privacy Risks — P8: Sharing of data with third parties', url: 'https://owasp.org/www-project-top-10-privacy-risks/' },
      ],
    },
  },
  analyze(ctx) {
    const t = ctx.ts;
    const findings: RuleFinding[] = [];
    for (const call of ctx.index.calls) {
      const sink = sinkOf(ctx, call);
      if (!sink) continue;
      for (const arg of call.arguments) {
        if (t.isStringLiteralLike(strip(ctx, arg))) continue;
        if (!sink.coveredByNgb016) {
          const s = sensitiveValue(ctx, arg);
          if (s) {
            findings.push({
              node: call,
              message: `${sink.label} receives ${s.category === 'payment' ? 'payment data' : 'a credential'} ('${s.strongest.match.term}'); analytics data is copied to a third-party processor and retained.`,
              confidence: s.confidence,
              severity: 'medium',
              evidenceKind: s.strongest.via === 'name' ? 'pattern' : 'heuristic',
              evidence: [`sink: ${sink.label}`, ...s.evidence],
            });
            break;
          }
        }
        if (sink.kind !== 'event') continue;
        const pii = directNames(ctx, arg).find(personalDataName);
        if (pii) {
          findings.push({
            node: call,
            message: `${sink.label} sends personal data ('${pii}') in an analytics event; use an opaque user ID instead.`,
            confidence: 'medium',
            severity: 'low',
            evidenceKind: 'heuristic',
            evidence: [`sink: ${sink.label}`, `payload contains '${pii}'`],
          });
          break;
        }
      }
    }
    return findings;
  },
});
