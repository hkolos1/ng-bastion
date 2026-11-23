import { describe, expect, it } from 'vitest';
import { one } from './helpers.js';

const PRE = `import { HttpClient } from '@angular/common/http';\nimport { ActivatedRoute } from '@angular/router';\ndeclare const TOKEN_URL: string;\n`;

describe('NGB023 missing OAuth state validation', () => {
  it('reports a code exchange that never reads state (medium)', async () => {
    const res = await one('NGB023', `${PRE}export class Callback {
  constructor(private http: HttpClient, private route: ActivatedRoute) {}
  run() {
    const code = this.route.snapshot.queryParamMap.get('code');
    return this.http.post(TOKEN_URL, { grant_type: 'authorization_code', code, client_id: 'spa' });
  }
}`);
    expect(res).toHaveLength(1);
    expect(res[0]!.confidence).toBe('medium');
  });

  it('reads state but never compares it → low; URLSearchParams form also recognized', async () => {
    const res = await one('NGB023', `${PRE}export class Callback {
  constructor(private http: HttpClient, private route: ActivatedRoute) {}
  run() {
    const q = this.route.snapshot.queryParamMap;
    console.log(q.get('state'));
    const body = new URLSearchParams();
    body.set('grant_type', 'authorization_code');
    body.set('code', q.get('code')!);
    return this.http.post(TOKEN_URL, body.toString());
  }
}`);
    expect(res).toHaveLength(1);
    expect(res[0]!.confidence).toBe('low');
  });

  it('reports an authorization URL without state', async () => {
    const res = await one('NGB023', `export function login(clientId: string) { location.href = \`https://idp.example.com/authorize?response_type=code&client_id=\${clientId}&redirect_uri=x\`; }`);
    expect(res).toHaveLength(1);
    expect(res[0]!.severity).toBe('medium');
  });

  it('safe: state stored, sent and compared', async () => {
    expect(await one('NGB023', `${PRE}export class Auth {
  constructor(private http: HttpClient, private route: ActivatedRoute) {}
  login() {
    const state = crypto.randomUUID();
    sessionStorage.setItem('oauth_state', state);
    location.href = \`https://idp.example.com/authorize?response_type=code&client_id=spa&state=\${state}\`;
  }
  callback() {
    const q = this.route.snapshot.queryParamMap;
    if (q.get('state') !== sessionStorage.getItem('oauth_state')) throw new Error('state mismatch');
    return this.http.post(TOKEN_URL, { grant_type: 'authorization_code', code: q.get('code') });
  }
}`)).toEqual([]);
  });

  it('false-positive regression: refresh-token grants and library configs are ignored', async () => {
    expect(await one('NGB023', `${PRE}export class R { constructor(private http: HttpClient) {} refresh(t: string) { return this.http.post(TOKEN_URL, { grant_type: 'refresh_token', refresh_token: t }); } }
export const cfg = { issuer: 'https://idp', responseType: 'code', clientId: 'spa' };`)).toEqual([]);
  });
});
