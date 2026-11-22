import { DOCUMENT } from '@angular/common';
import { TestBed } from '@angular/core/testing';
import { Seo, canonicalUrl } from './seo.service';

describe('Seo', () => {
  it('builds trailing-slash canonical URLs', () => {
    expect(canonicalUrl('/')).toBe('https://ngbastion.dev/');
    expect(canonicalUrl('/docs/configuration')).toBe('https://ngbastion.dev/docs/configuration/');
    expect(canonicalUrl('/rules/ngb001/?q=1#x')).toBe('https://ngbastion.dev/rules/ngb001/');
  });

  it('sets title, description, canonical, Open Graph and Twitter tags without duplicates', () => {
    const seo = TestBed.inject(Seo);
    const doc = TestBed.inject(DOCUMENT);
    seo.set({ title: 'A', description: 'first description', path: '/docs' });
    seo.set({ title: 'B | NgBastion', description: 'second description', path: '/rules/ngb002' });
    expect(doc.title).toBe('B | NgBastion');
    expect(doc.querySelectorAll('link[rel="canonical"]')).toHaveLength(1);
    expect(doc.querySelector('link[rel="canonical"]')!.getAttribute('href')).toBe('https://ngbastion.dev/rules/ngb002/');
    expect(doc.querySelectorAll('meta[property="og:title"]')).toHaveLength(1);
    expect(doc.querySelector('meta[property="og:url"]')!.getAttribute('content')).toBe('https://ngbastion.dev/rules/ngb002/');
    expect(doc.querySelector('meta[name="description"]')!.getAttribute('content')).toBe('second description');
    expect(doc.querySelector('meta[name="twitter:image"]')!.getAttribute('content')).toBe('https://ngbastion.dev/brand/social-preview.png');
  });

  it('writes JSON-LD as text, escapes "<" and replaces it on the next page', () => {
    const seo = TestBed.inject(Seo);
    const doc = TestBed.inject(DOCUMENT);
    seo.set({ title: 'x', description: 'description', path: '/', jsonLd: { name: '</script><b>' } });
    const script = doc.querySelector('script[data-ngb-jsonld]')!;
    expect(script.textContent).toContain('\\u003c/script>');
    expect(script.children).toHaveLength(0);
    seo.set({ title: 'y', description: 'description', path: '/docs' });
    expect(doc.querySelector('script[data-ngb-jsonld]')).toBeNull();
  });
});
