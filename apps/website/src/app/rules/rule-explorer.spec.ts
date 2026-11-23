import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { RuleExplorer } from './rule-explorer';

describe('RuleExplorer', () => {
  const render = () => {
    TestBed.configureTestingModule({ providers: [provideRouter([])] });
    const fixture = TestBed.createComponent(RuleExplorer);
    fixture.detectChanges();
    return { fixture, cmp: fixture.componentInstance, el: fixture.nativeElement as HTMLElement };
  };
  const rows = (el: HTMLElement) => el.querySelectorAll('tbody tr a.rule-id');

  it('lists every generated rule with a link to its page', () => {
    const { cmp, el } = render();
    expect(rows(el)).toHaveLength(cmp.rules.length);
    expect(el.querySelector('a.rule-id')!.getAttribute('href')).toBe('/rules/ngb001');
    expect(el.querySelector('.rule-count')!.textContent).toContain(`${cmp.rules.length} of ${cmp.rules.length} rules`);
  });

  it('combines severity, CWE, applicability, level and text filters, and resets them', () => {
    const { fixture, cmp, el } = render();
    const select = (label: string, value: string) => {
      const filter = Array.from(el.querySelectorAll('ngb-filter-select')).find(f => f.querySelector('span')?.textContent === label)!;
      filter.querySelector('button')!.click();
      fixture.detectChanges();
      const option = Array.from(filter.querySelectorAll<HTMLElement>('[role=option]')).find(o => o.textContent!.trim().startsWith(value))!;
      option.click();
      fixture.detectChanges();
    };
    select('Category', cmp.categories[0]);
    expect(cmp.shown().length).toBeGreaterThan(0);
    expect(cmp.shown().every((r) => r.category === cmp.categories[0])).toBe(true);
    (el.querySelector('.rule-reset') as HTMLButtonElement).click();
    fixture.detectChanges();
    expect(el.querySelector('[role=combobox] span')!.textContent).toBe('All');
    select('Severity', 'critical');
    expect(cmp.shown().every((r) => r.severity === 'critical')).toBe(true);
    expect(rows(el).length).toBe(cmp.shown().length);
    cmp.reset();
    select('CWE', 'CWE-79');
    expect(cmp.shown().length).toBeGreaterThan(0);
    expect(cmp.shown().every((r) => r.cwe.includes('CWE-79'))).toBe(true);
    select('Applies to', 'Server / SSR');
    expect(cmp.shown().every((r) => r.applies === 'Server / SSR' && r.cwe.includes('CWE-79'))).toBe(true);
    cmp.reset();
    select('Recommended', 'warn');
    expect(cmp.shown().every((r) => r.level === 'warn')).toBe(true);
    cmp.reset();
    const input = el.querySelector('input[type="search"]') as HTMLInputElement;
    input.value = 'no matching rule';
    input.dispatchEvent(new Event('input'));
    fixture.detectChanges();
    expect(rows(el)).toHaveLength(0);
    expect(el.querySelector('tbody')!.textContent).toContain('No rule matches');
    input.value = 'ngb100';
    input.dispatchEvent(new Event('input'));
    fixture.detectChanges();
    expect(Array.from(rows(el)).map((a) => a.textContent)).toEqual(['NGB100']);
    (el.querySelector('.rule-reset') as HTMLButtonElement).click();
    fixture.detectChanges();
    expect(rows(el)).toHaveLength(cmp.rules.length);
  });
});
