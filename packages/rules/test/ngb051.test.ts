import { describe, expect, it } from 'vitest';
import { NG, findings, one } from './helpers.js';

const cls = (body: string) => `${NG}import { SecurityContext } from '@angular/core';
@Component({ selector: 'app-x', template: '<div [innerHTML]="content"></div>' })
export class X {
  private sanitizer = inject(DomSanitizer);
  content: unknown = '';
${body}
}`;

describe('NGB051 mismatched Angular sanitization context', () => {
  it('reports URL-sanitized values trusted as HTML or resource URL (through const and ??)', async () => {
    const res = await one('NGB051', cls(`  a(v: string) {
    const html = this.sanitizer.sanitize(SecurityContext.URL, v) ?? '';
    this.content = this.sanitizer.bypassSecurityTrustHtml(html);
  }
  b(v: string) { this.content = this.sanitizer.bypassSecurityTrustResourceUrl(this.sanitizer.sanitize(SecurityContext.URL, v)!); }
  c(v: string, el: HTMLElement) { el.innerHTML = this.sanitizer.sanitize(SecurityContext.STYLE, v) ?? ''; }`));
    expect(res.map((f) => f.message.match(/as (\w+)/)![1])).toEqual(['HTML', 'RESOURCE_URL', 'HTML']);
    expect(res.every((f) => f.severity === 'high' && f.confidence === 'high')).toBe(true);
  });

  it('reports SecurityContext.NONE and ngx-markdown with sanitization disabled', async () => {
    const res = await findings('NGB051', {
      'src/app/a.ts': cls(`  a(v: string) { return this.sanitizer.sanitize(SecurityContext.NONE, v); }`),
      'src/app/app.config.ts': `import { SecurityContext } from '@angular/core';
import { provideMarkdown } from 'ngx-markdown';
export const appConfig = { providers: [provideMarkdown({ sanitize: SecurityContext.NONE })] };`,
      'src/app/md.ts': `import { Component } from '@angular/core';
@Component({ selector: 'app-md', template: '<markdown [data]="md" [disableSanitizer]="true"></markdown>' })
export class Md { md = ''; }`,
    });
    expect(res).toHaveLength(3);
    expect(res.map((f) => f.severity).sort()).toEqual(['high', 'high', 'medium']);
  });

  it('safe: matching contexts and sanitized values bound without bypass', async () => {
    expect(await one('NGB051', cls(`  a(v: string) { this.content = this.sanitizer.bypassSecurityTrustHtml(this.sanitizer.sanitize(SecurityContext.HTML, v) ?? ''); }
  b(v: string) { this.content = this.sanitizer.sanitize(SecurityContext.HTML, v); }
  c(v: string, el: HTMLElement) { el.innerHTML = this.sanitizer.sanitize(SecurityContext.HTML, v) ?? ''; }
  d(v: string) { this.content = this.sanitizer.bypassSecurityTrustUrl(this.sanitizer.sanitize(SecurityContext.URL, v) ?? ''); }`))).toEqual([]);
  });

  it('false-positive regression: other sanitize() methods and markdown configured safely', async () => {
    expect(await findings('NGB051', {
      'src/app/a.ts': `import DOMPurify from 'dompurify';
export function f(el: HTMLElement, v: string) { el.innerHTML = DOMPurify.sanitize(v); }
class Custom { sanitize(_c: number, v: string) { return v; } }
export function g(el: HTMLElement, v: string) { el.innerHTML = new Custom().sanitize(4, v); }`,
      'src/app/app.config.ts': `import { SecurityContext } from '@angular/core';
import { provideMarkdown } from 'ngx-markdown';
export const appConfig = { providers: [provideMarkdown({ sanitize: SecurityContext.HTML })] };`,
      'src/app/md.ts': `import { Component } from '@angular/core';
@Component({ selector: 'app-md', template: '<markdown [data]="md" [disableSanitizer]="false"></markdown>' })
export class Md { md = ''; }`,
    })).toEqual([]);
  });
});
