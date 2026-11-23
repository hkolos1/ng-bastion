import { describe, expect, it } from 'vitest';
import { findings } from './helpers.js';
import { wildcardFeatures } from '../src/rules/ngb062-permissive-permissions-policy.js';

const firebase = (value: string, key = 'Permissions-Policy') => JSON.stringify({ hosting: { headers: [{ source: '**', headers: [{ key, value }] }] } });

describe('NGB062 permissive Permissions-Policy', () => {
  it('parses both header syntaxes', () => {
    expect(wildcardFeatures('Permissions-Policy', 'camera=*, geolocation=(self "https://a.example"), payment=(*)')).toEqual(['camera', 'payment']);
    expect(wildcardFeatures('Feature-Policy', "microphone *; geolocation 'self'")).toEqual(['microphone']);
  });

  it('reports wildcard grants in hosting configs, _headers and server code', async () => {
    const res = await findings('NGB062', {
      'firebase.json': firebase('camera=*, microphone=*'),
      'public/_headers': '/*\n  Feature-Policy: geolocation *\n',
      'src/server.ts': `export function f(res: { setHeader(k: string, v: string): void }) { res.setHeader('Permissions-Policy', 'accelerometer=*'); }`,
    });
    expect(res).toHaveLength(3);
    expect(res.map((f) => f.severity).sort()).toEqual(['low', 'medium', 'medium']);
  });

  it('safe: self / explicit origins / disabled features', async () => {
    expect(await findings('NGB062', { 'firebase.json': firebase('camera=(), microphone=(self), geolocation=(self "https://maps.example.com")') })).toEqual([]);
  });

  it('false-positive regression: wildcard for harmless features, other headers', async () => {
    expect(await findings('NGB062', {
      'firebase.json': firebase('fullscreen=*, picture-in-picture=*'),
      'vercel.json': JSON.stringify({ headers: [{ source: '/(.*)', headers: [{ key: 'Access-Control-Allow-Origin', value: '*' }] }] }),
    })).toEqual([]);
  });
});
