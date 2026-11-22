import { describe, expect, it } from 'vitest';
import { NG, findings, one } from './helpers.js';

const cls = (body: string) => `${NG}
export class LoginComponent {
  private route = inject(ActivatedRoute);
  private router = inject(Router);
${body}
}`;
const RET = `const returnUrl = this.route.snapshot.queryParamMap.get('returnUrl') ?? '/';`;

describe('NGB011 untrusted redirect', () => {
  it('reports a query parameter assigned to location.href (high confidence, full trace)', async () => {
    const res = await one('NGB011', cls(`  done() {
    ${RET}
    window.location.href = returnUrl;
  }`));
    expect(res).toHaveLength(1);
    expect(res[0]!.severity).toBe('high');
    expect(res[0]!.confidence).toBe('high');
    expect(res[0]!.trace!.map((s) => s.kind)).toEqual(['source', 'assignment', 'sink']);
  });

  it('reports location.assign/replace, window.open and document.location', async () => {
    const res = await one('NGB011', `const u = new URLSearchParams(location.search).get('next') ?? '';
location.assign(u);
location.replace(u);
window.open(u);
document.location = u;`);
    expect(res.map((f) => f.location.line)).toEqual([2, 3, 4, 5]);
  });

  it('follows redirect helpers across files', async () => {
    const res = await findings('NGB011', {
      'src/app/redirect.ts': `export function redirectTo(url: string) { window.location.href = url; }`,
      'src/app/page.ts': `import { redirectTo } from './redirect';\nredirectTo(window.location.hash.slice(1));`,
    });
    expect(res).toHaveLength(1);
    expect(res[0]!.location.file).toBe('src/app/redirect.ts');
    expect(new Set(res[0]!.trace!.map((s) => s.file))).toEqual(new Set(['src/app/redirect.ts', 'src/app/page.ts']));
  });

  it('negative: Angular Router navigation is internal', async () => {
    expect(await one('NGB011', cls(`  done() { ${RET} this.router.navigateByUrl(returnUrl); this.router.navigate([returnUrl]); }`))).toEqual([]);
  });

  it('negative: constant destinations and pinned prefixes', async () => {
    expect(await one('NGB011', `location.href = '/home';
window.open('https://docs.example.com/guide');
location.href = '/orders/' + location.hash.slice(1);
location.href = \`https://shop.example.com/p/\${location.hash.slice(1)}\`;`)).toEqual([]);
  });

  it('safe equivalent: same-origin check and relative-path check suppress the finding', async () => {
    expect(await one('NGB011', cls(`  a() {
    ${RET}
    const target = new URL(returnUrl, location.origin);
    if (target.origin === location.origin) window.location.href = target.href;
  }
  b() {
    ${RET}
    if (!returnUrl.startsWith('/') || returnUrl.startsWith('//')) return;
    location.assign(returnUrl);
  }
  c() {
    ${RET}
    const ALLOWED = new Set(['example.com']);
    if (ALLOWED.has(new URL(returnUrl).hostname)) location.href = returnUrl;
  }`))).toEqual([]);
  });

  it('weak check lowers confidence to medium, custom validator to low', async () => {
    const res = await one('NGB011', `${NG}
function isSafe(u: string) { return u.length < 100; }
export class X {
  constructor(private route: ActivatedRoute) {}
  a() { ${RET} if (returnUrl.includes('example.com')) location.href = returnUrl; }
  b() { ${RET} if (returnUrl.startsWith('/')) location.href = returnUrl; }
  c() { ${RET} if (isSafe(returnUrl)) location.href = returnUrl; }
}`);
    expect(res.map((f) => f.confidence)).toEqual(['medium', 'medium', 'low']);
    expect(res[2]!.evidence.join('\n')).toMatch(/custom validator isSafe/);
  });

  it('false-positive regression: a guard on an unrelated variable does not count', async () => {
    const res = await one('NGB011', cls(`  done(other: string) {
    ${RET}
    if (other.startsWith('/') && !other.startsWith('//')) location.href = returnUrl;
  }`));
    expect(res).toHaveLength(1);
  });

  it('false-positive regression: String.replace is not location.replace', async () => {
    expect(await one('NGB011', `const s = location.hash.replace('#', '');`)).toEqual([]);
  });
});
