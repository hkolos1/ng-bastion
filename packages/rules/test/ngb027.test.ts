import { describe, expect, it } from 'vitest';
import { NG, findings, one } from './helpers.js';

describe('NGB027 sensitive data in DOM attributes', () => {
  it('reports template attribute bindings and hidden inputs carrying credentials', async () => {
    const res = await one('NGB027', `${NG}@Component({ selector: 'x', template: \`
  <div [attr.data-token]="session.accessToken"></div>
  <input type="hidden" name="k" [value]="apiKey">
\` })
export class X { session = { accessToken: '' }; apiKey = ''; }`);
    expect(res).toHaveLength(2);
    expect(res[0]!.snippet).toBeUndefined();
  });

  it('reports setAttribute, Renderer2.setAttribute and dataset writes', async () => {
    const res = await findings('NGB027', {
      'src/app/a.ts': `${NG}export class A {
  constructor(private r: Renderer2, private el: ElementRef<HTMLElement>) {}
  run(password: string, cardNumber: string, token: { accessToken: string }) {
    this.el.nativeElement.setAttribute('data-secret', password);
    this.r.setAttribute(this.el.nativeElement, 'title', cardNumber);
    this.el.nativeElement.dataset.auth = token.accessToken;
  }
}`,
    });
    expect(res).toHaveLength(3);
  });

  it('safe: non-sensitive data, masked values and method names', async () => {
    expect(await one('NGB027', `${NG}@Component({ selector: 'x', template: \`
  <div [attr.data-user]="userId" [title]="card.last4" [attr.aria-label]="showPassword ? 'hide' : 'show'"></div>
  <input type="text" [value]="password">
  <span [id]="getToken()"></span>
\` })
export class X { userId = 1; card = { last4: '' }; showPassword = false; password = ''; getToken() { return ''; } }`)).toEqual([]);
  });

  it('false-positive regression: names inside string literals (translation keys) are not values', async () => {
    expect(await one('NGB027', `${NG}@Component({ selector: 'x', template: \`<input type="password" placeholder="{{ 'login.form.password.placeholder' | translate }}" [title]="'token.help' | translate">\` })
export class X {}`)).toEqual([]);
  });

  it('false-positive regression: component inputs, interpolated literal text and formatter arguments', async () => {
    expect(await one('NGB027', `${NG}@Component({ selector: 'x', template: \`
  <bit-svg [content]="noCredentials"></bit-svg>
  <app-row [label]="password"></app-row>
  <a id="tab-managed-credentials-{{ r.id }}">x</a>
  <button [title]="getCopyText(credential)"></button>
\` })
export class X { noCredentials = ''; password = ''; r = { id: 1 }; credential = ''; getCopyText(c: string) { return c; } }`)).toEqual([]);
  });

  it('false-positive regression: CSRF tokens and non-DOM setAttribute', async () => {
    expect(await one('NGB027', `${NG}@Component({ selector: 'x', template: '<meta name="csrf" [attr.content]="csrfToken">' })
export class X { csrfToken = ''; }
const fake = { setAttribute: (_a: string, _b: string) => 0 };
export function f(password: string) { fake.setAttribute('data-p', password); }`)).toEqual([]);
  });
});
