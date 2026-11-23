import { describe, expect, it } from 'vitest';
import { NG, findings, one } from './helpers.js';

describe('NGB038 sensitive form submission target', () => {
  it('reports plain-HTTP and bound actions on forms with password / card fields', async () => {
    const res = await findings('NGB038', {
      'src/app/a.ts': `${NG}@Component({ selector: 'a', template: '<form action="http://login.example.com/session" method="post"><input type="password" name="pw"></form>' })
export class A {}`,
      'src/app/b.ts': `${NG}@Component({ selector: 'b', template: '<form [action]="target" method="post"><input name="cardNumber" autocomplete="cc-number"></form>' })
export class B { target = ''; }`,
    });
    expect(res.map((r) => r.severity).sort()).toEqual(['high', 'medium']);
  });

  it('reports index.html forms posting card data to another origin (low)', async () => {
    const res = await findings('NGB038', {
      'src/index.html': '<form action="https://acs.bank.example/3ds" method="post"><input name="cvv"></form>',
      'src/main.ts': 'export {};',
    });
    expect(res).toHaveLength(1);
    expect(res[0]!.confidence).toBe('low');
  });

  it('safe: ngSubmit forms without action, same-origin actions, non-sensitive forms', async () => {
    expect(await one('NGB038', `${NG}@Component({ selector: 'a', template: \`
  <form (ngSubmit)="submit()"><input type="password" formControlName="password"></form>
\` })
export class A { submit() {} }
@Component({ selector: 'b', template: '<form action="/login" method="post"><input type="password" name="p"></form><form action="http://search.example.com"><input name="q"></form>' })
export class B {}`)).toEqual([]);
  });

  it('false-positive regression: localhost development actions', async () => {
    expect(await one('NGB038', `${NG}@Component({ selector: 'a', template: '<form action="http://localhost:4200/login"><input type="password"></form>' })
export class A {}`)).toEqual([]);
  });
});
