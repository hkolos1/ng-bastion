import { DOCUMENT } from '@angular/common';
import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { HomePage } from './home-page';
import { LANDING, SHOWCASE } from './showcase';

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
    expect(el.querySelector('h1 .hl')!.textContent).toBe('Angular');
    expect(el.querySelectorAll('h1 .line')).toHaveLength(2);
    expect(el.textContent).toContain('npm install --save-dev ngbastion');
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

describe('HomePage data-flow engine and Angular-aware comparison', () => {
  it('walks the real NGB001 trace through the showcase source, ending at the sink', () => {
    TestBed.configureTestingModule({ providers: [provideRouter([])] });
    const fixture = TestBed.createComponent(HomePage);
    fixture.detectChanges();
    const el = fixture.nativeElement as HTMLElement;
    const nodes = el.querySelectorAll('.flow-node');
    expect(nodes).toHaveLength(SHOWCASE.flow.steps.length);
    expect(nodes[0]!.classList).toContain('k-source');
    expect(nodes[nodes.length - 1]!.classList).toContain('k-sink');
    expect(el.querySelector('.flow-code')!.textContent).toContain('queryParamMap');
    expect(el.querySelector('.flow-verdict')!.textContent).toContain('NGB001');
  });

  it('shows verdicts that come from scanning the snippets at build time', () => {
    TestBed.configureTestingModule({ providers: [provideRouter([])] });
    const fixture = TestBed.createComponent(HomePage);
    fixture.detectChanges();
    const items = Array.from((fixture.nativeElement as HTMLElement).querySelectorAll('.compare-item'));
    expect(items.map((i) => i.querySelector('.verdict')!.textContent!.trim())).toEqual(
      LANDING.comparison.map((c) => (c.findings.length ? `${c.findings[0]!.ruleId}reported` : 'no findings')),
    );
    expect(LANDING.comparison[0]!.findings).toEqual([]);
    expect(LANDING.comparison[1]!.findings.map((f) => f.ruleId)).toContain('NGB001');
  });
});
