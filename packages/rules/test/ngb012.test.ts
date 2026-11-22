import { describe, expect, it } from 'vitest';
import { NG, findings, one } from './helpers.js';

describe('NGB012 unsafe navigation scheme', () => {
  it('reports untrusted data assigned to anchor href and iframe src', async () => {
    const res = await one('NGB012', `const a = document.createElement('a');
a.href = new URLSearchParams(location.search).get('link') ?? '';
const f = document.querySelector('iframe') as HTMLIFrameElement;
f.src = window.name;
a.setAttribute('href', location.hash.slice(1));`);
    expect(res.map((x) => x.location.line)).toEqual([2, 4, 5]);
    expect(res.every((x) => x.confidence === 'high' && x.severity === 'high')).toBe(true);
  });

  it('reports location.href from postMessage data', async () => {
    const res = await one('NGB012', `window.addEventListener('message', (e: MessageEvent) => { location.href = e.data.url; });`);
    expect(res).toHaveLength(1);
    expect(res[0]!.trace![0]!.description).toBe('MessageEvent.data');
  });

  it('pattern: dynamic javascript: URL construction', async () => {
    const res = await one('NGB012', `declare const code: string;\nconst a = document.createElement('a');\na.href = 'javascript:' + code;`);
    expect(res).toHaveLength(1);
    expect(res[0]!.evidenceKind).toBe('pattern');
  });

  it('negative: constant javascript:void(0) and constant URLs', async () => {
    expect(await one('NGB012', `const a = document.createElement('a');\na.href = 'javascript:void(0)';\na.href = 'https://example.com';`)).toEqual([]);
  });

  it('safe equivalent: protocol allowlist, scheme regex and https prefix check', async () => {
    expect(await one('NGB012', `const raw = location.hash.slice(1);
const a = document.createElement('a');
const u = new URL(raw, location.origin);
if (['https:', 'http:'].includes(u.protocol)) a.href = u.href;
if (/^https?:\\/\\//i.test(raw)) a.href = raw;
if (raw.startsWith('https://')) window.open(raw);`)).toEqual([]);
  });

  it('scheme and host validation are independent', async () => {
    const code = `const raw = location.hash.slice(1);\nif (raw.startsWith('https://')) location.href = raw;`;
    expect(await one('NGB011', code)).toHaveLength(1); // scheme fixed but host free
    expect(await one('NGB012', code)).toEqual([]);
    const code2 = `const raw = location.hash.slice(1);\nconst ok = new Set(['a.com']);\nif (ok.has(new URL(raw).hostname)) location.href = raw;`;
    expect(await one('NGB011', code2)).toEqual([]);
    expect(await one('NGB012', code2)).toHaveLength(1); // javascript://a.com/… still has hostname a.com
  });

  it('cross-file: helper assigns an untyped nativeElement? only typed anchors count', async () => {
    const res = await findings('NGB012', {
      'src/app/link.ts': `export function setLink(a: HTMLAnchorElement, href: string) { a.href = href; }`,
      'src/app/page.ts': `${NG}import { setLink } from './link';\nexport class P { constructor(private route: ActivatedRoute) {} go(a: HTMLAnchorElement) { setLink(a, this.route.snapshot.queryParams['u']); } }`,
    });
    expect(res).toHaveLength(1);
    expect(res[0]!.location.file).toBe('src/app/link.ts');
  });
});
