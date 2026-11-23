import { describe, expect, it } from 'vitest';
import { findings, one } from './helpers.js';

describe('NGB066 sensitive data copied to the clipboard', () => {
  it('reports credentials and card data written to the clipboard', async () => {
    const res = await one('NGB066', `import { Clipboard } from '@angular/cdk/clipboard';
export class C {
  constructor(private clipboard: Clipboard) {}
  accessToken = '';
  a() { navigator.clipboard.writeText(this.accessToken); }
  b(cardNumber: string) { this.clipboard.copy(cardNumber); }
  c(user: { password: string }) { return navigator.clipboard.writeText(user.password); }
}`);
    expect(res).toHaveLength(3);
    expect(res.every((f) => f.severity === 'low')).toBe(true);
  });

  it('reports [cdkCopyToClipboard] bindings', async () => {
    const res = await findings('NGB066', {
      'src/app/c.ts': `import { Component } from '@angular/core';
@Component({ selector: 'x', template: '<button [cdkCopyToClipboard]="apiKey">copy</button>' })
export class C { apiKey = ''; }`,
    });
    expect(res).toHaveLength(1);
  });

  it('safe: non-sensitive values, masked values', async () => {
    expect(await one('NGB066', `export class C {
  a(orderReference: string, maskedCardNumber: string, shareUrl: string) {
    navigator.clipboard.writeText(orderReference);
    navigator.clipboard.writeText(maskedCardNumber);
    navigator.clipboard.writeText(shareUrl);
  }
}`)).toEqual([]);
  });

  it('false-positive regression: boolean/metadata names and project copy() methods', async () => {
    expect(await one('NGB066', `class Store { copy(v: string) { return v; } }
export function f(s: Store, passwordPolicy: string, tokenExpiry: string) { s.copy(passwordPolicy); navigator.clipboard.writeText(tokenExpiry); }`)).toEqual([]);
  });
});
