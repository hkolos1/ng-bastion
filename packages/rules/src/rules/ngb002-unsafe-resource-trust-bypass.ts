import { defineRule, lowerConfidence, type RuleFinding, type SinkContext } from '@ngbastion/plugin-api';
import { ANGULAR_SANITIZER_MODULES, constantPrefix, hasFixedOrigin, is, reportSink } from '../shared/common.js';

const METHODS: Record<string, { context: SinkContext; label: string }> = {
  bypassSecurityTrustUrl: { context: 'url', label: 'URL' },
  bypassSecurityTrustResourceUrl: { context: 'resource-url', label: 'resource URL' },
  bypassSecurityTrustScript: { context: 'script', label: 'script' },
};

export const ngb002 = defineRule({
  meta: {
    id: 'NGB002',
    name: 'Unsafe resource trust bypass',
    category: 'angular-xss',
    defaultSeverity: 'high',
    cwe: ['CWE-79', 'CWE-829'],
    docs: {
      description:
        'Reports `bypassSecurityTrustUrl()`, `bypassSecurityTrustResourceUrl()` and `bypassSecurityTrustScript()` calls whose argument is traced to an untrusted source. Constant URLs are not reported. When the value is a fixed `https://host/` prefix with only a dynamic path/query, confidence is lowered because the destination origin cannot change.',
      rationale:
        'Resource URLs decide what is loaded into `<iframe src>`, `<script src>` or `<object data>`. Marking an attacker-influenced URL as trusted lets the attacker choose the loaded document or script (`javascript:` URLs, attacker-hosted frames). Trusting a script value executes it directly.',
      patterns: [
        '`DomSanitizer.bypassSecurityTrustUrl / bypassSecurityTrustResourceUrl / bypassSecurityTrustScript(value)`',
        'Same source and propagation model as NGB001',
        'Fixed-origin detection: template literal or concatenation starting with a constant `https://host/` prefix',
        'Recognized sanitizers: `sanitizer.sanitize(SecurityContext.URL|RESOURCE_URL, …)`, `encodeURIComponent()` (URL contexts), `trustedSanitizers`',
      ],
      limitations: [
        'Allowlist checks performed before the call (e.g. `if (ALLOWED.includes(url))`) are not yet credited; such findings keep their confidence. Use an exception with justification.',
        '`bypassSecurityTrustStyle()` is not covered (style injection has a much smaller impact in modern browsers).',
      ],
      falsePositives: [
        'Embeds from a trusted provider whose ID comes from the URL (`https://www.youtube.com/embed/${id}`) are reported with reduced confidence; validate the ID format to be explicit.',
      ],
      remediation:
        'Avoid trust bypass for dynamic URLs. Build resource URLs from a constant origin plus a validated identifier (`/^[\\w-]{11}$/` for video IDs) or map keys to a constant allowlist. Never trust dynamic script values.',
      example: {
        unsafe: `this.frameUrl = this.sanitizer.bypassSecurityTrustResourceUrl(this.route.snapshot.queryParams['src']);`,
        safe: `const id = this.route.snapshot.queryParamMap.get('v') ?? '';
if (/^[\\w-]{11}$/.test(id)) {
  this.frameUrl = this.sanitizer.bypassSecurityTrustResourceUrl(\`https://www.youtube-nocookie.com/embed/\${id}\`);
}`,
      },
      references: [{ title: 'Angular security guide', url: 'https://angular.dev/best-practices/security' }],
    },
  },
  analyze(ctx) {
    const findings: RuleFinding[] = [];
    for (const call of ctx.index.calls) {
      const info = ctx.symbols.callee(call);
      const spec = info && METHODS[info.name];
      if (!info || !spec || info.declaration || !call.arguments[0]) continue;
      const certain = is(info.receiver, ANGULAR_SANITIZER_MODULES, 'DomSanitizer');
      if (!certain && info.receiver) continue;
      const fixed = spec.context !== 'script' && hasFixedOrigin(constantPrefix(ctx, call.arguments[0]));
      const results = reportSink({
        ctx,
        sink: call,
        value: call.arguments[0],
        context: spec.context,
        sinkDescription: `${info.name}() disables Angular ${spec.label} sanitization`,
        sinkCertain: certain,
        message: (f) => fixed
          ? `Untrusted data (${f.source.description}) is inserted into the path/query of a fixed-origin ${spec.label} marked as trusted with ${info.name}().`
          : `Untrusted data (${f.source.description}) is marked as a trusted ${spec.label} with ${info.name}().`,
        ...(fixed ? {} : { unresolvedMessage: `${info.name}() is applied to a dynamic value whose origin could not be determined; verify the destination is always trusted.` }),
        severity: (f) => (spec.context === 'script' && f ? 'critical' : undefined),
        extraEvidence: fixed ? ['the URL starts with a constant https origin; only path/query are dynamic'] : [],
      });
      for (const r of results) if (fixed) r.confidence = lowerConfidence(r.confidence);
      findings.push(...results);
    }
    return findings;
  },
});
