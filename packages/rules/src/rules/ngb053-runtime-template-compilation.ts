import type * as ts from 'typescript';
import { defineRule, type RuleFinding } from '@ngbastion/plugin-api';
import { flowEvidence, importedFrom, is, sinkStep, strip } from '../shared/common.js';
import { objectProp } from '../shared/http.js';

const CORE = '@angular/core';

export const ngb053 = defineRule({
  meta: {
    id: 'NGB053',
    name: 'Runtime template compilation from dynamic input',
    category: 'angular-xss',
    defaultSeverity: 'high',
    cwe: ['CWE-1336', 'CWE-79', 'CWE-94'],
    docs: {
      description:
        "Reports Angular components whose `template` is not a compile-time constant: `@Component({ template })` decorators and `Component({ template })(class {})` calls evaluated at runtime, and `ɵcompileComponent(type, { template })`. Templates traced to an untrusted source are reported with the trace (high / critical); other dynamic templates with low confidence.",
      rationale:
        "A component template is code, not data. With the JIT compiler in the bundle, a template built from user input lets the attacker write Angular template syntax (event bindings that call component methods, structural directives, interpolation into attributes) and raw HTML that Angular never sanitizes because it trusts its own templates. Angular's documentation is explicit: never generate templates from user data.",
      patterns: [
        '`@Component({ template: value })` / `Component({ template: value })(…)` where `value` is not a constant string (literals, `const` variables and constant template literals are constant)',
        '`ɵcompileComponent(type, { template: value })`',
        'Untrusted origin traced through the data-flow engine (URL, messages, HTTP responses, storage, user input) → high, critical for URL / message sources',
      ],
      limitations: [
        "Templates compiled by third-party dynamic-component libraries are not visible.",
        'Dynamic templates are only exploitable when the JIT compiler is shipped; the rule does not check the build configuration.',
      ],
      falsePositives: [
        'Templates assembled at runtime from constant fragments that the engine cannot prove constant (e.g. selected by a lookup) are reported with low confidence.',
      ],
      remediation:
        "Keep templates static. Render user-provided content through data bindings (`{{ text }}`, `[innerHTML]` with Angular's sanitizer) or choose among a fixed set of precompiled components (`NgComponentOutlet`, `ViewContainerRef.createComponent`).",
      example: {
        unsafe: `const Dynamic = Component({ selector: 'app-dyn', template: this.route.snapshot.queryParams['layout'] })(class {});`,
        safe: `@Component({ selector: 'app-dyn', template: '<p>{{ layout }}</p>' })
export class Dynamic { layout = this.route.snapshot.queryParams['layout']; }`,
      },
      references: [
        { title: 'Angular — Security: avoid generating templates from user input', url: 'https://angular.dev/best-practices/security#preventing-cross-site-scripting-xss' },
        { title: 'OWASP — Server/Client-side template injection', url: 'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/18-Testing_for_Server-side_Template_Injection' },
      ],
    },
  },
  analyze(ctx) {
    const t = ctx.ts;
    const findings: RuleFinding[] = [];
    const check = (node: ts.Node, config: ts.Expression | undefined, what: string) => {
      const tpl = objectProp(ctx, config, 'template');
      if (!tpl || ctx.symbols.constantString(tpl) !== undefined) return;
      const result = ctx.taint.trace(tpl, { context: 'html' });
      const flow = result.flows[0];
      if (flow) {
        findings.push({
          node: tpl,
          message: `${what} compiles a template built from untrusted data (${flow.source.description}); the attacker controls Angular template syntax and unsanitized HTML.`,
          confidence: flow.confidence,
          severity: flow.source.kind === 'url' || flow.source.kind === 'message' ? 'critical' : 'high',
          evidenceKind: 'dataflow',
          trace: [...flow.steps, sinkStep(ctx, tpl, `${what} template`)],
          evidence: flowEvidence(flow),
        });
        return;
      }
      if (result.constant) return;
      findings.push({
        node: tpl,
        message: `${what} compiles a template that is not a compile-time constant; verify no part of it can come from users.`,
        confidence: 'low',
        severity: 'medium',
        evidenceKind: 'heuristic',
        evidence: result.unresolved.slice(0, 3).map((u) => `origin not resolved: ${u.reason}`),
      });
    };
    const isComponent = (callee: ts.Expression) => {
      const c = strip(ctx, callee);
      const o = ctx.symbols.typeOrigin(c);
      if (is(o, CORE, 'Component')) return true;
      return importedFrom(ctx, c, CORE, 'Component');
    };
    for (const call of ctx.index.calls) {
      const info = ctx.symbols.callee(call);
      if (info?.name === 'ɵcompileComponent' && (info.origin?.module === CORE || !info.declaration)) {
        check(call, call.arguments[1], 'ɵcompileComponent()');
        continue;
      }
      if (!isComponent(call.expression)) continue;
      const inDecorator = t.isDecorator(call.parent);
      check(call, call.arguments[0], inDecorator ? '@Component()' : 'Component() at runtime');
    }
    return findings;
  },
});
