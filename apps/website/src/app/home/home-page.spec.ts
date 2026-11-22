import { DOCUMENT } from '@angular/common';
import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { HomePage } from './home-page';
import { SHOWCASE } from './showcase';

describe('HomePage', () => {
  const render = () => {
    TestBed.configureTestingModule({ providers: [provideRouter([])] });
    const fixture = TestBed.createComponent(HomePage);
    fixture.detectChanges();
    return { fixture, el: fixture.nativeElement as HTMLElement };
  };

  it('renders the brand, the tagline as the only h1 and JSON-LD', () => {
    const { el } = render();
    expect(el.querySelectorAll('h1')).toHaveLength(1);
    expect(el.querySelector('h1')!.textContent).toBe('Your Angular security stronghold.');
    expect(el.querySelector('.hero .label')!.textContent).toContain('NgBastion');
    expect(el.textContent).toContain('will not work until the first public release');
    expect(TestBed.inject(DOCUMENT).querySelector('script[data-ngb-jsonld]')!.textContent).toContain('"SoftwareApplication"');
  });

  it('shows one real finding at a time with its full source-to-sink trace', () => {
    const { fixture, el } = render();
    const tabs = Array.from(el.querySelectorAll<HTMLButtonElement>('.terminal-tabs [role="tab"]'));
    expect(tabs.map((t) => t.textContent)).toEqual(SHOWCASE.featured.map((f) => f.ruleId));
    for (const [i, f] of SHOWCASE.featured.entries()) {
      tabs[i]!.click();
      fixture.detectChanges();
      expect(tabs[i]!.getAttribute('aria-selected')).toBe('true');
      expect(el.querySelector('.finding-head .rule')!.textContent).toBe(f.ruleId);
      expect(el.querySelectorAll('.trace li')).toHaveLength(f.trace!.length);
      expect(el.querySelector('.trace li.k-source')).not.toBeNull();
      expect(el.querySelector('.trace li.k-sink')).not.toBeNull();
    }
    expect(el.querySelector('.terminal-caption')!.textContent).toContain('captured when this site was built');
  });

  it('supports arrow-key navigation between finding tabs', () => {
    const { fixture, el } = render();
    const first = el.querySelector<HTMLButtonElement>('.terminal-tabs [role="tab"]')!;
    first.dispatchEvent(new KeyboardEvent('keydown', { key: 'ArrowRight', bubbles: true }));
    fixture.detectChanges();
    expect(el.querySelector('.finding-head .rule')!.textContent).toBe(SHOWCASE.featured[1]!.ruleId);
    first.dispatchEvent(new KeyboardEvent('keydown', { key: 'ArrowLeft', bubbles: true }));
    fixture.detectChanges();
    expect(el.querySelector('.finding-head .rule')!.textContent).toBe(SHOWCASE.featured[0]!.ruleId);
  });
});
