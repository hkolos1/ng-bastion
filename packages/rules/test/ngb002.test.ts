import { describe, expect, it } from 'vitest';
import { NG, findings, one } from './helpers.js';

const cls = (body: string) => `${NG}
export class Embed {
  constructor(private s: DomSanitizer, private route: ActivatedRoute) {}
${body}
}`;

describe('NGB002 unsafe resource trust bypass', () => {
  it('reports an untrusted resource URL with high confidence', async () => {
    const [f] = await one('NGB002', cls(`  url = this.s.bypassSecurityTrustResourceUrl(this.route.snapshot.queryParams['src']);`));
    expect(f!.confidence).toBe('high');
    expect(f!.severity).toBe('high');
    expect(f!.trace!.at(-1)!.kind).toBe('sink');
  });

  it('lowers confidence when only the path of a fixed https origin is dynamic', async () => {
    const [f] = await one('NGB002', cls(`  url = this.s.bypassSecurityTrustResourceUrl(\`https://www.youtube-nocookie.com/embed/\${this.route.snapshot.queryParams['v']}\`);`));
    expect(f!.confidence).toBe('medium');
    expect(f!.evidence.join(' ')).toMatch(/constant https origin/);
  });

  it('escalates trusted scripts built from untrusted data to critical', async () => {
    const [f] = await one('NGB002', cls(`  run() { return this.s.bypassSecurityTrustScript(window.name); }`));
    expect(f!.severity).toBe('critical');
  });

  it('does not report constant URLs (safe equivalent)', async () => {
    expect(await one('NGB002', cls(`  url = this.s.bypassSecurityTrustResourceUrl('https://maps.example.com/embed?id=42');`))).toEqual([]);
  });

  it('does not report URL values sanitized for the URL context', async () => {
    expect(await one('NGB002', `${NG}import { SecurityContext } from '@angular/core';
export class X { constructor(private s: DomSanitizer) {}
  go() { const v = this.s.sanitize(SecurityContext.URL, location.hash) ?? ''; return this.s.bypassSecurityTrustUrl(v); } }`)).toEqual([]);
  });

  it('false-positive regression: an HTML sanitizer does not make a URL safe', async () => {
    const res = await one('NGB002', `${NG}import DOMPurify from 'dompurify';
export class X { constructor(private s: DomSanitizer) {} go() { return this.s.bypassSecurityTrustUrl(DOMPurify.sanitize(location.hash)); } }`);
    expect(res).toHaveLength(1);
  });

  it('follows a URL across files through an exported helper', async () => {
    const res = await findings('NGB002', {
      'src/app/url.ts': `export function fromFragment(): string { return decodeURIComponent(window.location.hash.slice(1)); }`,
      'src/app/frame.ts': `${NG}import { fromFragment } from './url';
export class Frame { constructor(private s: DomSanitizer) {} src = this.s.bypassSecurityTrustResourceUrl(fromFragment()); }`,
    });
    expect(res).toHaveLength(1);
    expect(res[0]!.trace![0]!.file).toBe('src/app/url.ts');
  });
  it('false-positive regression: Object.prototype method names (hasOwnProperty, toString) are not trust-bypass APIs', async () => {
    expect(await one('NGB002', `export function f(map: any, key: any, n: any) { if (map.hasOwnProperty(key)) return n.toString(16); return n.valueOf(); }`)).toEqual([]);
  });
});
