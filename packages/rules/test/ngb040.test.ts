import { describe, expect, it } from 'vitest';
import { NG, findings, one } from './helpers.js';

describe('NGB040 plaintext network transport', () => {
  it('reports http:// requests and ws:// sockets; credentials raise severity', async () => {
    const res = await one('NGB040', `${NG}export class C {
  constructor(private http: HttpClient) {}
  run(password: string) {
    this.http.get('http://api.example.com/items').subscribe();
    this.http.post('http://api.example.com/login', { password }).subscribe();
    new WebSocket('ws://realtime.example.com/feed');
    fetch('http://api.example.com/me', { credentials: 'include' });
  }
}`);
    expect(res.map((r) => r.severity).sort()).toEqual(['high', 'high', 'high', 'medium']);
  });

  it('reports plaintext URLs in production environment files', async () => {
    const res = await findings('NGB040', {
      'src/environments/environment.prod.ts': `export const environment = { production: true, apiUrl: 'http://api.example.com', socketUrl: 'ws://rt.example.com' };`,
      'src/environments/environment.development.ts': `export const environment = { production: false, apiUrl: 'http://api.example.com' };`,
    });
    expect(res).toHaveLength(2);
    expect(res.every((r) => r.location.file.endsWith('environment.prod.ts'))).toBe(true);
  });

  it('safe: https/wss and local development hosts', async () => {
    expect(await one('NGB040', `${NG}export class C {
  constructor(private http: HttpClient) {}
  run() {
    this.http.get('https://api.example.com/items').subscribe();
    new WebSocket('wss://realtime.example.com');
    fetch('http://localhost:3000/api');
    new EventSource('http://127.0.0.1:8080/events');
  }
}`)).toEqual([]);
  });

  it('false-positive regression: http URLs that are not request targets', async () => {
    expect(await one('NGB040', `export const docs = 'http://example.com/docs'; export const ns = { xmlns: 'http://www.w3.org/2000/svg' };`)).toEqual([]);
  });
});
