import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { NAV } from '../core/content';
import { SiteFooter } from './site-footer';

describe('SiteFooter', () => {
  it('links only to existing site routes and invents no external profiles or repository URLs', () => {
    TestBed.configureTestingModule({ providers: [provideRouter([])] });
    const fixture = TestBed.createComponent(SiteFooter);
    fixture.detectChanges();
    const el = fixture.nativeElement as HTMLElement;
    const hrefs = Array.from(el.querySelectorAll('a')).map((a) => a.getAttribute('href')!);
    const known = new Set(['/', '/playground', ...NAV.groups.flatMap((g) => g.items.map((i) => `/${i.slug}`))]);
    expect(hrefs.length).toBeGreaterThan(6);
    for (const h of hrefs) expect(known.has(h), h).toBe(true);
    expect(el.textContent).toContain('Repository private until the first public release');
    expect(el.textContent).toContain('MIT license');
  });
});
