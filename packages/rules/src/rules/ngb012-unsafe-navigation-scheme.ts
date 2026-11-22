import type * as ts from 'typescript';
import { defineRule, type AnalysisContext, type RuleFinding } from '@ngbastion/plugin-api';
import { constantPrefix, flowEvidence, memberName, methodCall, receiverOf, sinkStep, strip } from '../shared/common.js';
import { urlValidation, valueNames } from '../shared/url-guards.js';
import { navigationSinks, type NavigationSink } from './ngb011-untrusted-redirect.js';

const ELEMENT_URL_PROPS: Record<string, string[]> = {
  HTMLAnchorElement: ['href'],
  HTMLAreaElement: ['href'],
  HTMLIFrameElement: ['src'],
  HTMLFrameElement: ['src'],
  HTMLFormElement: ['action'],
  HTMLObjectElement: ['data'],
  HTMLEmbedElement: ['src'],
};
const DANGEROUS_SCHEME = /^\s*(javascript|vbscript|data)\s*:/i;

function elementSinks(ctx: AnalysisContext): NavigationSink[] {
  const out: NavigationSink[] = [];
  const elementType = (e: ts.Expression | undefined) => {
    if (!e) return undefined;
    const o = ctx.symbols.typeOrigin(e);
    return o?.module === 'dom' && ELEMENT_URL_PROPS[o.name] ? o.name : undefined;
  };
  for (const a of ctx.index.assignments) {
    const prop = memberName(ctx, a.left);
    const type = elementType(receiverOf(ctx, a.left));
    if (prop && type && ELEMENT_URL_PROPS[type]!.includes(prop)) {
      out.push({ node: a, value: a.right, description: `${type}.${prop}`, kind: 'element' });
    }
  }
  for (const call of ctx.index.calls) {
    const callee = strip(ctx, call.expression);
    if (memberName(ctx, callee) === 'setAttribute' && call.arguments[1]) {
      const type = elementType(receiverOf(ctx, callee));
      const attr = ctx.symbols.constantString(call.arguments[0]!)?.toLowerCase();
      if (type && attr && ELEMENT_URL_PROPS[type]!.includes(attr)) out.push({ node: call, value: call.arguments[1], description: `${type} ${attr} attribute`, kind: 'element' });
    }
    const r2 = methodCall(ctx, call, '@angular/core', ['Renderer2'], ['setAttribute', 'setProperty']);
    if (r2 && call.arguments[2]) {
      const key = ctx.symbols.constantString(call.arguments[1]!)?.toLowerCase();
      const type = elementType(call.arguments[0]);
      if (key && type && ELEMENT_URL_PROPS[type]!.includes(key)) out.push({ node: call, value: call.arguments[2], description: `Renderer2.${r2.info.name}(${type}, '${key}')`, kind: 'element' });
    }
  }
  return out;
}

export const ngb012 = defineRule({
  meta: {
    id: 'NGB012',
    name: 'Unsafe navigation scheme',
    category: 'navigation-auth',
    defaultSeverity: 'high',
    cwe: ['CWE-79', 'CWE-601'],
    docs: {
      description:
        'Reports URLs that may carry a dangerous scheme (`javascript:`, `vbscript:`, `data:`) into direct browser navigation or DOM URL properties that Angular does not sanitize: untrusted data reaching navigation sinks or anchor/iframe/form/object URL properties without scheme validation, and code that builds `javascript:` URLs from dynamic values.',
      rationale:
        'Navigating to `javascript:` executes script in the current origin. Angular sanitizes `[href]`/`[src]` template bindings, but direct DOM writes (`a.href = v`, `location.href = v`, `iframe.src = v`) and `window.open()` receive the raw string.',
      patterns: [
        'Sinks: `location.href = v`, `location = v`, `location.assign()/replace()`, `window.open()`, `anchor.href = v`, `iframe.src = v`, `form.action = v`, `object.data = v`, `setAttribute("href"|"src", v)` and `Renderer2.setAttribute/setProperty` on those element types',
        'Recognized scheme validation: `new URL(v).protocol` compared or allowlisted, `/^https?:/i.test(v)`, `v.startsWith("https://")`, relative paths (`v.startsWith("/")`), same-origin comparison',
        'A constant non-empty prefix (`"/profile/" + id`, `` `https://example.com/${x}` ``) fixes the scheme and is not reported',
        'Pattern: a constant `javascript:` / `data:` prefix concatenated with a dynamic value',
      ],
      limitations: [
        'Only validation inside the function containing the sink is considered.',
        'Calls to project validation functions in a guard are not analyzed; such findings are kept with low confidence.',
        'Template bindings are not reported because Angular sanitizes them.',
      ],
      falsePositives: [
        'Constant `javascript:void(0)` links are not reported; only dynamic values or dynamic `javascript:` construction are.',
      ],
      remediation:
        'Parse the URL with `new URL(value, location.origin)` and allow only `https:` (and `http:` if required) before assigning it, or use Angular template bindings which sanitize unsafe URLs.',
      example: {
        unsafe: `this.link.nativeElement.href = this.route.snapshot.queryParams['next'];`,
        safe: `const next = new URL(this.route.snapshot.queryParams['next'] ?? '/', location.origin);
if (next.protocol === 'https:') this.link.nativeElement.href = next.href;`,
      },
      references: [{ title: 'Angular security — URL sanitization', url: 'https://angular.dev/best-practices/security' }],
    },
  },
  analyze(ctx) {
    const findings: RuleFinding[] = [];
    for (const sink of [...navigationSinks(ctx), ...elementSinks(ctx)]) {
      const prefix = constantPrefix(ctx, sink.value);
      const whole = ctx.symbols.constantString(sink.value);
      if (prefix && DANGEROUS_SCHEME.test(prefix) && whole === undefined) {
        findings.push({
          node: sink.node,
          message: `A ${prefix.trim().split(':')[0]}: URL is built from a dynamic value and assigned to ${sink.description}; the value is executed as script on navigation.`,
          confidence: 'high',
          evidenceKind: 'pattern',
          evidence: [`constant prefix '${prefix.slice(0, 40)}' with a dynamic remainder`],
        });
        continue;
      }
      if (prefix) continue; // a constant prefix fixes the scheme
      const result = ctx.taint.trace(sink.value, { context: 'url' });
      const flow = result.flows[0];
      if (!flow) continue;
      const v = urlValidation(ctx, sink.node, valueNames(ctx, sink.value, result.names));
      if (v.scheme === 'strong') continue;
      findings.push({
        node: sink.node,
        message: `Untrusted data (${flow.source.description}) reaches ${sink.description} without scheme validation; a javascript: URL would execute script.`,
        confidence: v.scheme === 'custom' ? 'low' : flow.confidence,
        evidenceKind: 'dataflow',
        trace: [...flow.steps, sinkStep(ctx, sink.node, `${sink.description} accepts any URL scheme`)],
        evidence: [...flowEvidence(flow), ...v.evidence.map((e) => `guard: ${e}`)],
      });
    }
    return findings;
  },
});
