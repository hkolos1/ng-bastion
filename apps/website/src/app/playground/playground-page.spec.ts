import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { PLAYGROUND } from './playground-data';
import { PlaygroundPage, hitLines } from './playground-page';

describe('PlaygroundPage', () => {
  beforeEach(() => TestBed.configureTestingModule({ providers: [provideRouter([])] }));

  const render = () => {
    const fixture = TestBed.createComponent(PlaygroundPage);
    fixture.detectChanges();
    return { fixture, el: fixture.nativeElement as HTMLElement };
  };

  it('labels the page as a build-time demonstration', () => {
    expect(render().el.querySelector('.notice')!.textContent).toContain('this page does not scan arbitrary input');
  });

  it('shows real findings for unsafe variants and none for safe variants', () => {
    const { fixture, el } = render();
    for (const ex of PLAYGROUND.examples) {
      fixture.componentInstance.exampleId.set(ex.id);
      fixture.componentInstance.variant.set('unsafe');
      fixture.detectChanges();
      const ids = Array.from(el.querySelectorAll('.results .head a')).map((a) => a.textContent);
      expect(ids).toEqual(ex.variants.unsafe.findings.map((f) => f.ruleId));
      expect(ids.length).toBeGreaterThan(0);
      fixture.componentInstance.variant.set('safe');
      fixture.detectChanges();
      expect(el.querySelector('.results h3')!.textContent).toBe('No findings');
    }
  });

  it('switches via the radio controls', () => {
    const { fixture, el } = render();
    const safe = el.querySelector<HTMLInputElement>('input[name="variant"][value="safe"]')!;
    safe.checked = true;
    safe.click();
    fixture.detectChanges();
    expect(el.querySelector('.pg-panel h2')!.textContent).toContain('safe variant');
  });

  it('highlights source, sink and trace lines of the shown file', () => {
    const v = PLAYGROUND.examples[0]!.variants.unsafe;
    const lines = hitLines(v, v.files[0]!.name);
    for (const f of v.findings) expect(lines.has(f.location.line)).toBe(true);
    expect(hitLines(PLAYGROUND.examples[0]!.variants.safe, v.files[0]!.name).size).toBe(0);
  });
});
