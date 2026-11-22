import { DOCUMENT } from '@angular/common';
import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { HomePage } from './home-page';
import { SHOWCASE } from './showcase';

describe('HomePage', () => {
  it('renders the brand, tagline and the real showcase scan with traces', () => {
    TestBed.configureTestingModule({ providers: [provideRouter([])] });
    const fixture = TestBed.createComponent(HomePage);
    fixture.detectChanges();
    const el = fixture.nativeElement as HTMLElement;
    expect(el.querySelector('h1')!.textContent).toBe('NgBastion');
    expect(el.querySelector('.tagline')!.textContent).toBe('Your Angular security stronghold.');
    const findings = el.querySelectorAll('.terminal .finding');
    expect(findings).toHaveLength(SHOWCASE.featured.length);
    expect(el.querySelectorAll('.terminal .trace li.k-source').length).toBe(SHOWCASE.featured.length);
    expect(el.textContent).toContain(`${SHOWCASE.total} findings`);
    expect(el.textContent).toContain('will not work until the first public release');
    expect(TestBed.inject(DOCUMENT).querySelector('script[data-ngb-jsonld]')!.textContent).toContain('"SoftwareApplication"');
  });
});
