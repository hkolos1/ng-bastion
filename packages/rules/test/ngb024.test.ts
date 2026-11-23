import { describe, expect, it } from 'vitest';
import { one } from './helpers.js';

const IMP = `import { AuthConfig } from 'angular-oauth2-oidc';\n`;

describe('NGB024 weakened OAuth/OIDC client configuration', () => {
  it('reports disabled PKCE, implicit flow and requireHttps:false in an AuthConfig', async () => {
    const res = await one('NGB024', `${IMP}export const authConfig: AuthConfig = {
  issuer: 'https://login.example.com',
  clientId: 'spa',
  responseType: 'id_token token',
  disablePKCE: true,
  requireHttps: false,
};`);
    expect(res.map((f) => f.severity).sort()).toEqual(['high', 'high', 'medium']);
  });

  it('reports PKCE plain in an object and in a URL', async () => {
    const res = await one('NGB024', `export const a = { client_id: 'spa', code_challenge_method: 'plain' };
export const u = 'https://idp/authorize?code_challenge_method=plain&response_type=code';`);
    expect(res).toHaveLength(2);
  });

  it('reports angular-oauth2-oidc AuthConfig without responseType (implicit default)', async () => {
    const res = await one('NGB024', `${IMP}export const c = new AuthConfig({ issuer: 'https://idp', clientId: 'spa' });`);
    expect(res).toHaveLength(1);
    expect(res[0]!.confidence).toBe('medium');
  });

  it('safe: code flow with defaults', async () => {
    expect(await one('NGB024', `${IMP}export const c: AuthConfig = { issuer: 'https://idp', clientId: 'spa', responseType: 'code', requireHttps: true, disablePKCE: false };`)).toEqual([]);
  });

  it('false-positive regression: unrelated objects with similar keys are ignored', async () => {
    expect(await one('NGB024', `export const ui = { disablePKCE: true, requireHttps: false, responseType: 'token' };
export const s3 = { region: 'eu', requireHttps: false };`)).toEqual([]);
  });
});
