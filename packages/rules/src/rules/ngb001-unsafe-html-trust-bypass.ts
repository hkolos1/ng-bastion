import { defineRule, type RuleFinding } from '@ngbastion/plugin-api';
import { ANGULAR_SANITIZER_MODULES, enclosingClass, is, reportSink, storedName, templateBindingsOf } from '../shared/common.js';

export const ngb001 = defineRule({
  meta: {
    id: 'NGB001',
    name: 'Unsafe HTML trust bypass',
    category: 'angular-xss',
    defaultSeverity: 'high',
    cwe: ['CWE-79'],
    docs: {
      description:
        'Reports calls to `DomSanitizer.bypassSecurityTrustHtml()` whose argument can be traced to an untrusted source (URL, postMessage, user input, storage, HTTP response). Bypass calls on values whose origin cannot be resolved are reported with low confidence; constant HTML and values passed through a recognized HTML sanitizer are not reported.',
      rationale:
        '`bypassSecurityTrustHtml()` does not sanitize anything. It wraps a string so Angular skips its built-in HTML sanitization when the value is bound to `[innerHTML]`. Any attacker-controlled markup in that string executes as script in your origin (DOM XSS).',
      patterns: [
        '`sanitizer.bypassSecurityTrustHtml(value)` where `sanitizer` is `DomSanitizer` from `@angular/platform-browser` (constructor injection or `inject()`)',
        'Values traced through variables, class fields, function parameters/returns, services across files, template literals, string methods, RxJS `map`/`switchMap`/`tap` and Angular `signal`/`computed`/`toSignal`',
        'Untrusted sources: ActivatedRoute query/route params and fragment, `location.*`, `document.URL`, `window.name`, `MessageEvent.data`, input element values, `[(ngModel)]` bindings, Web Storage reads, HttpClient/fetch responses',
        'Recognized sanitizers: `DomSanitizer.sanitize(SecurityContext.HTML, …)`, `DOMPurify.sanitize()`, functions listed in `trustedSanitizers`. URL encoding (`encodeURIComponent()`, `encodeURI()`) is not HTML escaping: such flows are still reported, with lowered confidence',
      ],
      limitations: [
        'Values coming from component `input()`s or `@Input()`s are reported as unresolved (the parent binding is not followed).',
        'Data flowing through unmodeled libraries is propagated with reduced confidence; data stored in Maps, global state libraries (NgRx, NGXS) or closures is not followed.',
        'Validation in a separate function (e.g. an allowlist check) is not recognized as sanitization unless configured in `trustedSanitizers`.',
      ],
      falsePositives: [
        'HTTP responses from your own trusted CMS are reported (medium confidence). If the backend guarantees sanitized HTML, document an exception with a justification.',
        'Custom sanitizers are not trusted by default; register them in `trustedSanitizers` after review.',
      ],
      remediation:
        'Bind untrusted HTML with `[innerHTML]` directly and let Angular sanitize it, or sanitize explicitly (`DOMPurify.sanitize()` / `sanitizer.sanitize(SecurityContext.HTML, v)`) before any trust bypass. Reserve `bypassSecurityTrustHtml()` for constant or fully server-controlled markup.',
      example: {
        unsafe: `const html = this.route.snapshot.queryParamMap.get('preview') ?? '';
this.content = this.sanitizer.bypassSecurityTrustHtml(html);`,
        safe: `const html = this.route.snapshot.queryParamMap.get('preview') ?? '';
this.content = html; // <div [innerHTML]="content"> is sanitized by Angular`,
      },
      references: [
        { title: 'Angular security guide — Sanitization and security contexts', url: 'https://angular.dev/best-practices/security' },
      ],
    },
  },
  analyze(ctx) {
    const findings: RuleFinding[] = [];
    for (const call of ctx.index.calls) {
      const info = ctx.symbols.callee(call);
      if (!info || info.name !== 'bypassSecurityTrustHtml' || info.declaration || !call.arguments[0]) continue;
      const certain = is(info.receiver, ANGULAR_SANITIZER_MODULES, 'DomSanitizer');
      if (!certain && info.receiver) continue; // a different, known type with the same method name
      const stored = storedName(ctx, call);
      const bindings = stored ? templateBindingsOf(ctx, enclosingClass(ctx, call), stored) : [];
      findings.push(...reportSink({
        ctx,
        sink: call,
        value: call.arguments[0],
        context: 'html',
        sinkDescription: 'bypassSecurityTrustHtml() disables Angular HTML sanitization',
        sinkCertain: certain,
        message: (f) => `Untrusted data (${f.source.description}) is marked as trusted HTML with bypassSecurityTrustHtml(); Angular will not sanitize it.`,
        unresolvedMessage: 'bypassSecurityTrustHtml() is applied to a dynamic value whose origin could not be determined; verify it can never contain attacker-controlled markup.',
        extraEvidence: bindings,
      }));
    }
    return findings;
  },
});
