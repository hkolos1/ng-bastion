import { defineRule, type Confidence, type RuleFinding, type Severity, type SourceLocation } from '@ngbastion/plugin-api';
import { relative } from '../shared/common.js';
import { htmlTags } from '../shared/files.js';
import { isPlaintextRemote } from '../shared/http.js';
import { classifyName } from '../shared/sensitivity.js';

const SENSITIVE_AUTOCOMPLETE = /\b(current-password|new-password|one-time-code|cc-number|cc-csc|cc-exp)\b/i;

interface Field {
  attrs: Map<string, string>;
}

/** Why an input carries a credential or card data, if it does. */
function sensitiveField(f: Field): string | undefined {
  const type = f.attrs.get('type')?.toLowerCase();
  if (type === 'password') return 'password field';
  const ac = f.attrs.get('autocomplete');
  if (ac && SENSITIVE_AUTOCOMPLETE.test(ac)) return `autocomplete="${ac}"`;
  for (const k of ['name', 'formcontrolname', 'id']) {
    const v = f.attrs.get(k);
    if (v && classifyName(v)) return `${k}="${v}"`;
  }
  return undefined;
}

interface FormTarget {
  location: SourceLocation;
  where: string;
  /** Constant action, or null when bound dynamically. */
  action: string | null;
  fields: string[];
}

function assess(f: FormTarget): { severity: Severity; confidence: Confidence; why: string } | undefined {
  if (f.action === null) return { severity: 'medium', confidence: 'medium', why: 'its action is bound to a dynamic value' };
  if (isPlaintextRemote(f.action, 'http')) return { severity: 'high', confidence: 'high', why: `it posts over plain HTTP to ${f.action}` };
  if (/^\s*http:/i.test(f.action)) return undefined; // local development host
  if (/^\s*https?:\/\//i.test(f.action) || /^\s*\/\//.test(f.action)) return { severity: 'low', confidence: 'low', why: `it posts to another origin (${f.action})` };
  return undefined;
}

export const ngb038 = defineRule({
  meta: {
    id: 'NGB038',
    name: 'Sensitive form submission target',
    category: 'sensitive-data',
    defaultSeverity: 'high',
    cwe: ['CWE-319', 'CWE-201'],
    docs: {
      description:
        "Reports `<form>` elements that contain password, one-time-code or payment-card fields and are submitted natively to an insecure or uncontrolled destination: a plain-HTTP `action` (high), an `[action]` / `[attr.action]` binding (medium), or an absolute URL on another origin (low). Covers component templates and index.html.",
      rationale:
        "A native form submission sends every field as-is to the `action` URL. Over HTTP the password or card number is readable and modifiable on the network; a bound action lets whoever controls the bound value (URL parameter, API response) receive the credentials; posting card data to a third-party origin is sometimes intended (3-D Secure, hosted payment pages) but must be reviewed.",
      patterns: [
        'Sensitive fields: `type="password"`, `autocomplete="current-password|new-password|one-time-code|cc-number|cc-csc|cc-exp"`, `name` / `formControlName` / `id` classified as credential or payment data (`password`, `cvv`, `cardNumber`, …)',
        'Targets: static `action="http://…"` (non-local host), `[action]` / `[attr.action]` bindings, absolute `https://` actions',
        'Forms without `action` (submitted through `(ngSubmit)` / HttpClient) are not reported',
      ],
      limitations: [
        'Fields are attributed to the closest preceding `<form>` in the template (document order); fields placed after a form closes but before the next one are attributed to the earlier form.',
        'Forms built with Renderer2 / DOM APIs are not covered; dynamic `form.action = …` assignments are handled by NGB012 (scheme) and NGB011 (redirects).',
      ],
      falsePositives: [
        'Intended posts to a payment provider (3-D Secure ACS, hosted payment page) are reported with low confidence; document an exception.',
      ],
      remediation:
        "Submit credentials and card data only to your own origin over HTTPS, preferably through Angular `HttpClient` instead of native form posts. Keep `action` constant; never bind it to data you do not fully control.",
      example: {
        unsafe: `<form [action]="loginUrl" method="post"><input type="password" name="password"></form>`,
        safe: `<form [formGroup]="login" (ngSubmit)="submit()"><input type="password" formControlName="password"></form>`,
      },
      references: [
        { title: 'OWASP ASVS — V9 Communication (TLS for all connections)', url: 'https://owasp.org/www-project-application-security-verification-standard/' },
        { title: 'MDN — <form action>', url: 'https://developer.mozilla.org/docs/Web/HTML/Element/form#action' },
      ],
    },
  },
  analyze(ctx) {
    const targets: FormTarget[] = [];
    for (const tpl of ctx.templates) {
      const forms = tpl.elements.filter((e) => e.name.toLowerCase() === 'form');
      if (!forms.length) continue;
      // Elements are in document order and forms cannot nest: a field belongs to the closest preceding <form>.
      const owned = new Map<(typeof forms)[number], string[]>(forms.map((f) => [f, []]));
      let current: (typeof forms)[number] | undefined;
      for (const e of tpl.elements) {
        if (e.name.toLowerCase() === 'form') current = e;
        else if (current && ['input', 'textarea', 'select'].includes(e.name.toLowerCase())) {
          const why = sensitiveField({ attrs: new Map(e.attributes.filter((a) => !a.bound).map((a) => [a.name.toLowerCase(), a.value])) });
          if (why) owned.get(current)!.push(why);
        }
      }
      for (const form of forms) {
        const action = form.attributes.find((a) => a.name.toLowerCase() === 'action');
        const fields = owned.get(form)!;
        if (!action || !fields.length) continue;
        targets.push({ location: form.location, where: `<form> in ${tpl.component}`, action: action.bound ? null : action.value, fields });
      }
    }
    const index = ctx.project.indexHtml;
    const html = index && ctx.readFile(index);
    if (index && html) {
      for (const form of htmlTags(html, index, ['form'])) {
        const end = html.indexOf('</form>', form.index);
        const body = html.slice(form.index, end < 0 ? undefined : end);
        const fields = htmlTags(body, index, ['input', 'textarea', 'select']).map((f) => sensitiveField(f)).filter((x): x is string => !!x);
        if (fields.length && form.attrs.has('action')) targets.push({ location: form.location, where: `<form> in ${relative(ctx, index)}`, action: form.attrs.get('action')!, fields });
      }
    }
    const findings: RuleFinding[] = [];
    for (const f of targets) {
      const a = assess(f);
      if (!a) continue;
      findings.push({
        location: f.location,
        message: `${f.where} submits sensitive fields (${f.fields.slice(0, 3).join(', ')}) natively, and ${a.why}.`,
        confidence: a.confidence,
        severity: a.severity,
        evidenceKind: 'pattern',
        evidence: [`action: ${f.action === null ? '(bound)' : f.action}`, ...f.fields.map((x) => `field: ${x}`)],
      });
    }
    return findings;
  },
});
