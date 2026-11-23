import { TestBed } from '@angular/core/testing';
import { Router, provideRouter } from '@angular/router';
import { NAV, loadPage } from '../core/content';
import { RenderedContent } from './rendered-content';

describe('RenderedContent', () => {
  beforeEach(() => TestBed.configureTestingModule({ providers: [provideRouter([])] }));

  const slugs = NAV.groups.flatMap(g => g.items.map(item => item.slug)).filter(slug => slug !== 'playground');
  it.each(slugs)('renders %s through Angular sanitization without stripping anything', async slug => {
    const warn = vi.spyOn(console, 'warn');
    try {
      const page = (await loadPage(slug))!;
      const fixture = TestBed.createComponent(RenderedContent);
      fixture.componentRef.setInput('blocks', page.blocks);
      fixture.componentRef.setInput('slug', slug);
      fixture.detectChanges();
      expect(warn.mock.calls.some(([message]) => String(message).includes('sanitizing HTML stripped'))).toBe(false);
      const el = fixture.nativeElement as HTMLElement;
      for (const h of page.headings) expect(el.querySelector(`[id="${h.id}"]`), `${slug}#${h.id}`).not.toBeNull();
    } finally {
      warn.mockRestore();
    }
  });

  it('turns every markdown code fence into a highlighted CodeBlock with a copy button', async () => {
    const page = (await loadPage('docs/configuration'))!;
    const fixture = TestBed.createComponent(RenderedContent);
    fixture.componentRef.setInput('blocks', page.blocks);
    fixture.componentRef.setInput('slug', page.slug);
    fixture.detectChanges();
    const el = fixture.nativeElement as HTMLElement;
    const fences = page.blocks.filter((b) => b.kind === 'code');
    expect(el.querySelectorAll('ngb-code-block')).toHaveLength(fences.length);
    expect(el.querySelectorAll('ngb-code-block .copy-btn')).toHaveLength(fences.length);
    expect(el.querySelector('.code-body .line span[class^="sk-"]')).not.toBeNull();
    expect(el.querySelector('.prose-block pre')).toBeNull(); // no plain <pre> left in prose
    expect(el.querySelector('aside.callout-caution .callout-title')!.textContent).toContain('TypeScript configs execute code');
  });

  it('routes same-site links through the Angular router and leaves external links alone', () => {
    const router = TestBed.inject(Router);
    const nav = vi.spyOn(router, 'navigateByUrl').mockResolvedValue(true);
    const fixture = TestBed.createComponent(RenderedContent);
    fixture.componentRef.setInput('blocks', [{ kind: 'html', html: '<p><a href="/docs/limitations/">in</a> <a href="https://cwe.mitre.org/">out</a></p>' }]);
    fixture.componentRef.setInput('slug', 'docs');
    fixture.detectChanges();
    const [internal, external] = Array.from((fixture.nativeElement as HTMLElement).querySelectorAll('a'));
    const click = (a: HTMLAnchorElement) => {
      const e = new MouseEvent('click', { bubbles: true, cancelable: true, button: 0 });
      a.dispatchEvent(e);
      return e.defaultPrevented;
    };
    expect(click(internal!)).toBe(true);
    expect(nav).toHaveBeenCalledWith('/docs/limitations/');
    nav.mockClear();
    // jsdom cannot navigate; stop the browser default after the component's handler ran.
    const stop = (e: Event) => e.preventDefault();
    document.addEventListener('click', stop);
    click(external!);
    document.removeEventListener('click', stop);
    expect(nav).not.toHaveBeenCalled();
  });
});
