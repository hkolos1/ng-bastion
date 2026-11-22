import { describe, expect, it } from 'vitest';
import { findings, one } from './helpers.js';

describe('NGB015 sensitive payment data persistence', () => {
  it('reports card number and CVV serialized into localStorage (critical/high, snippet redacted)', async () => {
    const res = await one('NGB015', `declare const form: { cardNumber: string; cvv: string };
localStorage.setItem('checkout', JSON.stringify({ cardNumber: form.cardNumber, cvv: form.cvv }));`);
    expect(res).toHaveLength(1);
    expect(res[0]!.severity).toBe('critical');
    expect(res[0]!.confidence).toBe('high');
    expect(res[0]!.snippet).toBeUndefined();
  });

  it('reports Luhn-valid literals, cookies and IndexedDB', async () => {
    const res = await one('NGB015', `localStorage.setItem('draft', '4111111111111111');
declare const pan: string;
document.cookie = 'pan=' + pan;
declare const store: IDBObjectStore;
declare const cvc: string;
store.add({ cvc }, 'card');`);
    expect(res.map((f) => f.location.line)).toEqual([1, 3, 6]);
  });

  it('card expiry alone is high (not critical) with medium confidence', async () => {
    const res = await one('NGB015', `declare const v: string;\nsessionStorage.setItem('cardExpiry', v);`);
    expect(res[0]!.severity).toBe('high');
    expect(res[0]!.confidence).toBe('medium');
  });

  it('cross-file: card number traced through a service field', async () => {
    const res = await findings('NGB015', {
      'src/app/pay.ts': `export class Pay { cardNumber = ''; }`,
      'src/app/save.ts': `import { Pay } from './pay';\nexport const save = (p: Pay) => localStorage.setItem('x', p.cardNumber);`,
    });
    expect(res).toHaveLength(1);
  });

  it('safe equivalent: opaque token, brand and last4 only', async () => {
    expect(await one('NGB015', `declare const r: { token: string; brand: string; last4: string };
localStorage.setItem('checkout', JSON.stringify({ paymentToken: r.token, cardBrand: r.brand, last4: r.last4 }));
declare const maskedPan: string;
localStorage.setItem('display', maskedPan);
localStorage.setItem('paymentId', 'pay_123');
localStorage.setItem('order', '1234567890123');`)).toEqual([]);
  });

  it('false-positive regression: masking before storage', async () => {
    expect(await one('NGB015', `declare const cardNumber: string;\nlocalStorage.setItem('card', cardNumber.slice(-4));\ndeclare function maskPan(x: string): string;\nlocalStorage.setItem('card2', maskPan(cardNumber));`)).toEqual([]);
  });
});
