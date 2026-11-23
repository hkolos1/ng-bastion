import { describe, expect, it } from 'vitest';
import { NG, one } from './helpers.js';

const CLS = (body: string) => `${NG}export class C {\n  constructor(private http: HttpClient, private route: ActivatedRoute) {}\n  run() {\n${body}\n  }\n}`;

describe('NGB039 JSONP request', () => {
  it('reports third-party JSONP (medium) and attacker-controlled JSONP URLs (high)', async () => {
    const res = await one('NGB039', CLS(`    this.http.jsonp('https://api.weather.example/today', 'callback').subscribe();
    this.http.jsonp(this.route.snapshot.queryParamMap.get('feed')!, 'cb').subscribe();`));
    expect(res.map((r) => r.severity).sort()).toEqual(['high', 'medium']);
  });

  it('reports same-origin JSONP with low confidence', async () => {
    const res = await one('NGB039', CLS(`    this.http.jsonp('/legacy/data', 'cb').subscribe();`));
    expect(res[0]!.confidence).toBe('low');
  });

  it('safe: HttpClient.get', async () => {
    expect(await one('NGB039', CLS(`    this.http.get('https://api.weather.example/today').subscribe();`))).toEqual([]);
  });

  it('false-positive regression: non-HttpClient jsonp()', async () => {
    expect(await one('NGB039', `const client = { jsonp: (_u: string, _c: string) => 0 }; client.jsonp('https://x.example', 'cb');`)).toEqual([]);
  });
});
