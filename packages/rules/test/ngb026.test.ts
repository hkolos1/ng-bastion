import { describe, expect, it } from 'vitest';
import { NG, one } from './helpers.js';

const CLS = (body: string) => `${NG}declare const environment: { apiUrl: string };
export class C {
  constructor(private http: HttpClient, private route: ActivatedRoute) {}
  run() {
${body}
  }
}`;

describe('NGB026 untrusted HTTP request destination', () => {
  it('reports a state-changing request whose path comes from a route parameter (CSPT)', async () => {
    const res = await one('NGB026', CLS(`    const id = this.route.snapshot.paramMap.get('id');
    this.http.delete(\`/api/projects/\${id}\`).subscribe();`));
    expect(res).toHaveLength(1);
    expect(res[0]!.severity).toBe('medium');
    expect(res[0]!.message).toMatch(/path traversal/);
  });

  it('reports a GET path segment with low severity and lowered confidence', async () => {
    const res = await one('NGB026', CLS(`    this.http.get(environment.apiUrl + '/items/' + this.route.snapshot.queryParams['item']).subscribe();`));
    expect(res).toHaveLength(1);
    expect(res[0]!.severity).toBe('low');
    expect(res[0]!.confidence).toBe('medium');
  });

  it('reports an attacker-chosen destination with credentials as high severity', async () => {
    const res = await one('NGB026', CLS(`    const target = this.route.snapshot.queryParamMap.get('callback')!;
    fetch(target, { method: 'POST', credentials: 'include', headers: { Authorization: 'Bearer x' } });`));
    expect(res).toHaveLength(1);
    expect(res[0]!.severity).toBe('high');
    expect(res[0]!.message).toMatch(/Authorization/);
  });

  it('safe: encoded or validated identifiers, query values, fixed URLs', async () => {
    expect(await one('NGB026', CLS(`    const id = this.route.snapshot.paramMap.get('id') ?? '';
    this.http.delete(\`/api/projects/\${encodeURIComponent(id)}\`).subscribe();
    if (/^[0-9]+$/.test(id)) this.http.put(\`/api/projects/\${id}\`, {}).subscribe();
    this.http.get(\`/api/search?q=\${this.route.snapshot.queryParams['q']}\`).subscribe();
    this.http.post('/api/projects', { id }).subscribe();
    this.http.get(\`/api/items/\${Number(id)}\`).subscribe();`))).toEqual([]);
  });

  it('false-positive regression: same-origin host validation and non-attacker sources', async () => {
    expect(await one('NGB026', CLS(`    const target = this.route.snapshot.queryParamMap.get('next')!;
    if (new URL(target, location.origin).origin !== location.origin) return;
    this.http.get(target).subscribe();
    this.http.get<{ next: string }>('/api/page').subscribe((p) => this.http.get(p.next).subscribe());`))).toEqual([]);
  });
});
