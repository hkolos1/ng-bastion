import { defineRule, type RuleFinding } from '@ngbastion/plugin-api';
import { is, memberName, receiverOf, strip } from '../shared/common.js';
import { hostingHeaders } from '../shared/files.js';

export const ngb050 = defineRule({
  meta: {
    id: 'NGB050',
    name: 'document.domain relaxation',
    category: 'cross-window',
    defaultSeverity: 'medium',
    cwe: ['CWE-942', 'CWE-346'],
    docs: {
      description:
        "Reports assignments to `document.domain` and responses that opt back into it with the `Origin-Agent-Cluster: ?0` header (in hosting configs, `_headers` files or server code).",
      rationale:
        "Setting `document.domain = 'example.com'` lets every page on every subdomain that does the same script your page directly — the same-origin policy is reduced to the registrable domain, so an XSS on a forgotten `blog.example.com` becomes an XSS on `app.example.com`. Browsers are removing the feature (origin-keyed agent clusters make the setter a no-op by default), and `Origin-Agent-Cluster: ?0` exists only to re-enable it.",
      patterns: [
        '`document.domain = value` where `document` is the DOM `Document` (also via `inject(DOCUMENT)`)',
        "`Origin-Agent-Cluster: ?0` in `firebase.json`, `vercel.json`, `staticwebapp.config.json`, `_headers`, or `setHeader('Origin-Agent-Cluster', '?0')`",
      ],
      limitations: [
        'Third-party scripts that set `document.domain` are not visible.',
        'Reading `document.domain` is not reported.',
      ],
      falsePositives: [
        'Legacy integrations that still require cross-subdomain scripting are reported; plan their migration to `postMessage`.',
      ],
      remediation:
        'Remove `document.domain` assignments and communicate between subdomains with `postMessage` (with strict origin checks, NGB007) or a shared backend. Do not send `Origin-Agent-Cluster: ?0`.',
      example: {
        unsafe: `document.domain = 'example.com';`,
        safe: `parentWindow.postMessage({ type: 'resize', height }, 'https://www.example.com');`,
      },
      references: [
        { title: 'MDN — Document.domain (deprecated)', url: 'https://developer.mozilla.org/docs/Web/API/Document/domain' },
        { title: 'Chrome — Origin-keyed agent clusters by default', url: 'https://developer.chrome.com/blog/document-domain-setter-deprecation' },
      ],
    },
  },
  analyze(ctx) {
    const findings: RuleFinding[] = [];
    for (const a of ctx.index.assignments) {
      const left = strip(ctx, a.left);
      if (memberName(ctx, left) !== 'domain' || !is(ctx.symbols.typeOrigin(receiverOf(ctx, left)!), 'dom', 'Document')) continue;
      findings.push({
        node: a,
        message: 'Assigning document.domain relaxes the same-origin policy to the parent domain; any subdomain that does the same can script this page.',
        confidence: 'high',
        evidenceKind: 'pattern',
        evidence: [`value: ${ctx.symbols.constantString(a.right) ?? '(dynamic)'}`],
      });
    }
    for (const h of hostingHeaders(ctx, 'Origin-Agent-Cluster')) {
      if (h.value.trim() !== '?0') continue;
      findings.push({ location: h.location, message: `${h.origin} sends Origin-Agent-Cluster: ?0, re-enabling document.domain relaxation.`, confidence: 'high', severity: 'low', evidenceKind: 'pattern', evidence: ['Origin-Agent-Cluster: ?0'] });
    }
    for (const call of ctx.index.calls) {
      const [k, v] = call.arguments;
      if (!k || !v || !['setHeader', 'set', 'header', 'append'].includes(memberName(ctx, strip(ctx, call.expression)) ?? '')) continue;
      if (/^origin-agent-cluster$/i.test(ctx.symbols.constantString(k) ?? '') && ctx.symbols.constantString(v)?.trim() === '?0') {
        findings.push({ node: call, message: 'Server sends Origin-Agent-Cluster: ?0, re-enabling document.domain relaxation.', confidence: 'high', severity: 'low', evidenceKind: 'pattern', evidence: ['Origin-Agent-Cluster: ?0'] });
      }
    }
    return findings;
  },
});
