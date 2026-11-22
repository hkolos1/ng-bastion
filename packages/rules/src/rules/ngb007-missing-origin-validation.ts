import type * as ts from 'typescript';
import { defineRule, type Confidence, type RuleFinding } from '@ngbastion/plugin-api';
import { findMessageHandlers, handlerScopes, messageReads, readCheck, referencesProp, type MessageHandler } from '../shared/messages.js';

const SENSITIVE_CALLS = new Set([
  'insertAdjacentHTML', 'write', 'writeln', 'eval', 'Function', 'setItem', 'navigate', 'navigateByUrl', 'open', 'assign', 'replace',
  'bypassSecurityTrustHtml', 'bypassSecurityTrustUrl', 'bypassSecurityTrustResourceUrl', 'bypassSecurityTrustScript',
  'get', 'post', 'put', 'patch', 'delete', 'request', 'fetch', 'setProperty', 'setAttribute', 'postMessage', 'set', 'next', 'dispatch',
]);
const SENSITIVE_PROPS = new Set(['innerHTML', 'outerHTML', 'srcdoc', 'href', 'src', 'location', 'cookie']);

/** Does the handler (or a helper it delegates the message to) perform a security-relevant operation? */
export function performsSensitiveWork(ctx: Parameters<typeof findMessageHandlers>[0], h: MessageHandler): boolean {
  const t = ctx.ts;
  let found = false;
  for (const s of handlerScopes(ctx, h)) {
    const visit = (n: ts.Node): void => {
      if (found) return;
      if (t.isCallExpression(n)) {
        const c = n.expression;
        const name = t.isIdentifier(c) ? c.text : t.isPropertyAccessExpression(c) ? c.name.text : '';
        if (SENSITIVE_CALLS.has(name)) found = true;
      }
      if (t.isBinaryExpression(n) && n.operatorToken.kind === t.SyntaxKind.EqualsToken && t.isPropertyAccessExpression(n.left) && SENSITIVE_PROPS.has(n.left.name.text)) found = true;
      t.forEachChild(n, visit);
    };
    const body = (s.fn as { body?: ts.Node }).body;
    if (body) visit(body);
  }
  return found;
}

export const ngb007 = defineRule({
  meta: {
    id: 'NGB007',
    name: 'Missing origin validation',
    category: 'cross-window',
    defaultSeverity: 'high',
    cwe: ['CWE-346', 'CWE-940'],
    docs: {
      description:
        "Reports window `message` handlers that read `event.data` without an origin check that dominates the read. Strict checks — equality with a known origin, or membership in an allowlist array/Set — suppress the finding. Substring-style checks (`startsWith`, `endsWith`, `includes`/`indexOf` on the origin string, unanchored regular expressions) are reported as weak. Origin checks that do not guard the data use (logged, inverted, or performed after the read) do not count.",
      rationale:
        'Any window can send messages to yours (any page can open or frame your app). Without verifying `event.origin`, attacker pages can inject commands or data into your application. `event.origin.startsWith("https://trusted.com")` also matches `https://trusted.com.attacker.net`.',
      patterns: [
        "`window.addEventListener('message', fn)`, `window.onmessage = fn`, `Renderer2.listen('window', 'message', fn)`",
        "`@HostListener('window:message', ['$event'])` and component `host: { '(window:message)': 'onMessage($event)' }`",
        "`fromEvent(window, 'message').pipe(filter(...)).subscribe(fn)` (checks inside `filter` count)",
        'Reads: `event.data`, `event["data"]`, `({ data }) =>`, `const { data } = event`; one level of delegation (`this.handle(event)` / `service.process(event.data)`)',
        'Strict: `event.origin === ALLOWED`, `!==` + early return, `ALLOWED.includes(event.origin)`, `set.has(origin)`, `indexOf(origin) !== -1` on arrays, anchored regex `/^https:\\/\\/a\\.com$/.test(origin)`, and project validator functions whose body performs such a check',
      ],
      limitations: [
        'Handlers registered through helper libraries or stored in variables before registration are not discovered.',
        'Checks performed in a different function than the read (other than a validator called in the guard condition, or a guard around the delegating call) are not recognized.',
        'An exact comparison against a value that is itself attacker-controlled is still treated as strict.',
      ],
      falsePositives: [
        'Handlers that intentionally accept messages from any origin (public widget APIs) and only process inert data are reported with medium confidence; document an exception explaining why.',
      ],
      remediation:
        "Compare `event.origin` against an exact allowlist before touching `event.data`: `if (!ALLOWED_ORIGINS.includes(event.origin)) return;`. Also verify `event.source` when you expect a specific frame (NGB008) and validate the payload structure (NGB009).",
      example: {
        unsafe: `window.addEventListener('message', (e) => {
  if (e.origin.startsWith('https://partner.example')) this.apply(e.data);
});`,
        safe: `const ALLOWED = ['https://partner.example.com'];
window.addEventListener('message', (e) => {
  if (!ALLOWED.includes(e.origin)) return;
  this.apply(e.data);
});`,
      },
      references: [{ title: 'MDN — postMessage security concerns', url: 'https://developer.mozilla.org/docs/Web/API/Window/postMessage#security_concerns' }],
    },
  },
  analyze(ctx) {
    const findings: RuleFinding[] = [];
    for (const h of findMessageHandlers(ctx)) {
      const reads = messageReads(ctx, h);
      if (!reads.length) continue;
      const sensitive = performsSensitiveWork(ctx, h);
      let worst: { read: (typeof reads)[number]; check: 'weak' | undefined } | undefined;
      for (const read of reads) {
        const check = readCheck(ctx, h, read, 'origin');
        if (check === 'strict') continue;
        if (!worst || (worst.check === 'weak' && check === undefined)) worst = { read, check };
      }
      if (!worst) continue;
      const reg = ctx.location(h.registration);
      const where = `handler registered via ${h.how} at line ${reg.line}`;
      const referenced = referencesProp(ctx, h, 'origin');
      let confidence: Confidence;
      let message: string;
      if (worst.check === 'weak') {
        confidence = sensitive ? 'medium' : 'low';
        message = 'Message handler uses a weak origin check (substring or unanchored pattern) before processing event.data; look-alike origins such as https://trusted.com.attacker.net pass it.';
      } else {
        confidence = sensitive ? 'high' : 'medium';
        message = referenced
          ? 'Message handler references event.origin but the check does not guard the use of event.data.'
          : 'Message handler processes event.data without validating event.origin; any window can send it messages.';
      }
      findings.push({
        node: worst.read.node,
        message,
        confidence,
        evidenceKind: 'pattern',
        evidence: [
          where,
          sensitive ? 'handler performs security-relevant operations (DOM, navigation, storage, HTTP, state updates)' : 'no security-relevant operation identified in the handler',
          ...(worst.read.via.length ? [`message passed to a helper at line ${ctx.location(worst.read.via[0]!).line}`] : []),
        ],
      });
    }
    return findings;
  },
});
