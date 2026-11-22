import { defineRule, type RuleFinding } from '@ngbastion/plugin-api';
import { assessWrite, storageWrites } from '../shared/storage.js';

export const ngb015 = defineRule({
  meta: {
    id: 'NGB015',
    name: 'Sensitive payment data persistence',
    category: 'sensitive-data',
    defaultSeverity: 'critical',
    cwe: ['CWE-312', 'CWE-922'],
    docs: {
      description:
        'Reports cardholder data — primary account numbers (PAN), card verification codes (CVV/CVC) and card expiry stored next to them — written to `localStorage`, `sessionStorage`, IndexedDB or `document.cookie`. Evidence comes from storage keys, value and object-literal property names, declared types, names along the data flow, and Luhn-valid card-number literals.',
      rationale:
        'Browser storage is unencrypted at rest and readable by any script in the origin. Persisting card numbers expands the PCI DSS scope of the frontend; persisting CVV/CVC after authorization is forbidden by PCI DSS in all cases.',
      patterns: [
        'Storage writes as in NGB014, plus `document.cookie = "pan=…"`',
        'Names: `cardNumber`, `ccNumber`, `pan`, `cvv`, `cvc`, `cvv2`, `securityCode`, `track2`, `cardExpiry` (weak on its own)',
        '`localStorage.setItem("checkout", JSON.stringify({ cardNumber, cvv }))` — object literal keys are inspected',
        'Luhn-valid 13–19 digit literals reaching storage',
        'Not reported: `last4`, `maskedPan`, `cardBrand`, `paymentId`, opaque PSP payment tokens, hashed/masked values',
      ],
      limitations: [
        'Card data stored under neutral names with untyped values is not detected.',
        'Card data inside forms serialized wholesale (`JSON.stringify(this.form.value)`) is reported only when the form type or flow reveals card fields.',
        'Server-side storage and logging are out of scope.',
      ],
      falsePositives: [
        'A field named `pan` that is not a card number (e.g. a camera pan setting) can be reported; rename it or add a scoped exception.',
      ],
      remediation:
        'Never persist card data in the browser. Use your payment provider\'s hosted fields / iframe so card data never touches your code, and keep only the opaque token, brand and last four digits.',
      example: {
        unsafe: `localStorage.setItem('checkout', JSON.stringify({ cardNumber: this.form.value.cardNumber, cvv: this.form.value.cvv }));`,
        safe: `localStorage.setItem('checkout', JSON.stringify({ paymentToken: result.token, brand: result.brand, last4: result.last4 }));`,
      },
      references: [{ title: 'PCI DSS — Protect stored account data', url: 'https://www.pcisecuritystandards.org/' }],
    },
  },
  analyze(ctx) {
    const findings: RuleFinding[] = [];
    for (const w of storageWrites(ctx, { cookies: true })) {
      const a = assessWrite(ctx, w, 'payment');
      if (!a) continue;
      findings.push({
        node: w.node,
        message: `Payment card data is persisted in ${w.store}${w.key ? ` under '${w.key}'` : ''}; card numbers and verification codes must not be stored in the browser.`,
        confidence: a.confidence,
        severity: a.strong ? 'critical' : 'high',
        evidenceKind: a.keyEvidence && a.valueEvidence ? 'pattern' : 'heuristic',
        evidence: a.evidence,
        redactSnippet: true,
      });
    }
    return findings;
  },
});
