import type * as ts from 'typescript';
import { defineRule, type AnalysisContext, type Confidence, type RuleFinding } from '@ngbastion/plugin-api';
import { is, receiverOf, strip } from '../shared/common.js';
import { confidenceOf, describeEvidence, isRedacted, sensitivityOf, strongest, type SensitivityEvidence } from '../shared/sensitivity.js';

export { confidenceOf, strongest };

const RANK: Record<Confidence, number> = { low: 0, medium: 1, high: 2 };

const CONSOLE_METHODS = new Set(['log', 'info', 'warn', 'error', 'debug', 'trace', 'dir', 'table']);
const SENTRY_METHODS = new Set(['captureMessage', 'captureException', 'setUser', 'setContext', 'setExtra', 'setExtras', 'addBreadcrumb']);

/** Returns a sink label for logging / telemetry calls, or undefined. */
function logSink(ctx: AnalysisContext, call: ts.CallExpression): string | undefined {
  const t = ctx.ts;
  const callee = strip(ctx, call.expression);
  const info = ctx.symbols.callee(call);
  if (!info) return undefined;
  const name = info.name;
  const recv = receiverOf(ctx, callee);
  if (!recv) {
    if (name === 'gtag') return 'gtag()';
    if (SENTRY_METHODS.has(name) && info.origin?.module.startsWith('@sentry/')) return `Sentry ${name}()`;
    return undefined;
  }
  const recvText = strip(ctx, recv).getText().replace(/\s+/g, '');
  const ro = ctx.symbols.typeOrigin(recv);
  if (CONSOLE_METHODS.has(name) && (is(ro, ['dom', 'lib', '@types/node'], 'Console') || recvText === 'console' || recvText === 'window.console')) {
    return `console.${name}()`;
  }
  if (SENTRY_METHODS.has(name) && (ro?.module.startsWith('@sentry/') || recvText === 'Sentry')) return `Sentry.${name}()`;
  if (name === 'push' && /(^|\.)dataLayer$/.test(recvText)) return 'dataLayer.push()';
  if (name === 'capture' && (recvText === 'posthog' || ro?.module === 'posthog-js')) return 'posthog.capture()';
  if (/(^|\.)datadogLogs\.logger$/.test(recvText) && t.isPropertyAccessExpression(callee)) return `datadogLogs.logger.${name}()`;
  if (name === 'addAction' && /(^|\.)datadogRum$/.test(recvText)) return 'datadogRum.addAction()';
  if ((name === 'trackEvent' || name === 'trackTrace') && (/appInsights$/i.test(recvText) || ro?.module === '@microsoft/applicationinsights-web')) {
    return `appInsights.${name}()`;
  }
  return undefined;
}

export const ngb016 = defineRule({
  meta: {
    id: 'NGB016',
    name: 'Sensitive data logging',
    category: 'sensitive-data',
    defaultSeverity: 'high',
    cwe: ['CWE-532'],
    docs: {
      description:
        'Reports credentials (passwords, access/refresh/ID tokens, API keys, session IDs) and payment data (card number, CVV/CVC) passed to browser logging or telemetry APIs. Evidence comes from the value\'s own name, the properties of its declared type, names along its traced data flow, or a Luhn-valid card number literal. Values passed through a recognizable redaction step are not reported.',
      rationale:
        'Browser console output is visible to anyone with access to the device and is often captured by session-replay and error-tracking tools. Telemetry services store logged values on third-party infrastructure, outside your access controls and retention policies. Logged tokens can be replayed; logged card data puts the application in PCI DSS scope.',
      patterns: [
        '`console.log/info/warn/error/debug/trace/dir/table(…)` (type-resolved `Console`)',
        'Sentry `captureMessage/captureException/setUser/setContext/setExtra/addBreadcrumb` (imports from `@sentry/*`)',
        '`gtag(…)`, `dataLayer.push(…)`, `posthog.capture(…)`, `datadogLogs.logger.*(…)`, `datadogRum.addAction(…)`, `appInsights.trackEvent/trackTrace(…)`',
        'Sensitivity by head noun: `accessToken`, `refresh_token`, `password`, `apiKey`, `sessionId`, `cvv`, `cardNumber`, `pan`; metadata such as `tokenExpiry`, `passwordHint`, `maskedPan`, `last4` is ignored',
        'Redaction recognized: calls named `mask*`, `redact*`, `hash*`, `truncate*`, `.slice(-4)`, `.replace(…, "*")`',
      ],
      limitations: [
        'Generic objects (`console.log(user)`) are reported only when their declared type exposes a sensitive property; untyped objects are not inspected.',
        'Custom logger services are not treated as sinks unless they delegate to a modeled API inside the scanned code.',
        'Telemetry objects are matched by their conventional global/import names; renamed instances are missed.',
      ],
      falsePositives: [
        'Variables named like secrets that hold non-secret values (e.g. a boolean called `token`).',
        'Logging statements removed from production builds are still reported; consider removing them from source instead.',
      ],
      remediation:
        'Do not log credentials or payment data. Log stable identifiers (user ID, request ID) or a masked form (`****1234`). Configure telemetry SDKs with `beforeSend` scrubbing as a second line of defence.',
      example: {
        unsafe: `this.auth.login(creds).subscribe(res => console.log('login ok', res.accessToken));`,
        safe: `this.auth.login(creds).subscribe(res => console.log('login ok', { userId: res.userId }));`,
      },
      references: [{ title: 'OWASP Logging Cheat Sheet — data to exclude', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html#data-to-exclude' }],
    },
  },
  analyze(ctx) {
    const findings: RuleFinding[] = [];
    for (const call of ctx.index.calls) {
      const sink = logSink(ctx, call);
      if (!sink) continue;
      let best: { e: SensitivityEvidence; all: SensitivityEvidence[] } | undefined;
      for (const arg of call.arguments) {
        if (ctx.ts.isStringLiteralLike(strip(ctx, arg)) && !strip(ctx, arg).getText().match(/\d{13}/)) continue;
        const trace = ctx.taint.trace(arg, { context: 'generic' });
        if (isRedacted(ctx, arg, trace)) continue;
        const ev = sensitivityOf(ctx, arg, trace);
        const top = strongest(ev);
        if (top && (!best || RANK[confidenceOf(top)] > RANK[confidenceOf(best.e)])) best = { e: top, all: ev };
      }
      if (!best) continue;
      const what = best.e.match.category === 'payment' ? 'payment data' : 'a credential';
      findings.push({
        node: call,
        message: `${sink} receives ${what} ('${best.e.match.term}'); logged values are exposed to anyone with console or telemetry access.`,
        confidence: confidenceOf(best.e),
        evidenceKind: best.e.via === 'name' || best.e.via === 'literal' ? 'pattern' : 'heuristic',
        evidence: [`sink: ${sink}`, ...best.all.slice(0, 4).map(describeEvidence)],
        redactSnippet: best.e.via === 'literal',
      });
    }
    return findings;
  },
});
