import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { NAV } from '../core/content';
import { SiteFooter } from './site-footer';

describe('SiteFooter', () => {
  it('links to existing site routes plus only the author profile', () => {
    TestBed.configureTestingModule({ providers: [provideRouter([])] });
    const fixture = TestBed.createComponent(SiteFooter);
    fixture.detectChanges();
    const el = fixture.nativeElement as HTMLElement;
    const all = Array.from(el.querySelectorAll('a')).map((a) => a.getAttribute('href')!);
    expect(all.filter((h) => /^https?:/.test(h))).toEqual(['https://github.com/hkolos1']);
    const hrefs = all.filter((h) => !/^https?:/.test(h));
    const known = new Set(['/', '/playground', ...NAV.groups.flatMap((g) => g.items.map((i) => `/${i.slug}`))]);
    expect(hrefs.length).toBeGreaterThan(6);
    for (const h of hrefs) expect(known.has(h), h).toBe(true);
    expect(el.textContent).toContain('MIT License · Open Source');
    expect(el.textContent).toContain('Built by hkolos1');
  });
});
