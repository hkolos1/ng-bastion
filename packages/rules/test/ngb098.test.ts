import { describe, expect, it } from 'vitest';
import { findings, one } from './helpers.js';

describe('NGB098 TLS certificate validation disabled', () => {
  it('reports NODE_TLS_REJECT_UNAUTHORIZED=0 and rejectUnauthorized: false in code', async () => {
    const res = await one('NGB098', `import https from 'https';
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
process.env['NODE_TLS_REJECT_UNAUTHORIZED'] = 0 as unknown as string;
export const agent = new https.Agent({ rejectUnauthorized: false });
export const opts = { strictSSL: false };`);
    expect(res).toHaveLength(4);
    expect(res.every((f) => f.severity === 'high')).toBe(true);
  });

  it('reports .env files and package.json scripts (medium)', async () => {
    const res = await findings('NGB098', { 'src/main.ts': 'export {};', '.env': 'API=https://x\nexport NODE_TLS_REJECT_UNAUTHORIZED=0\n', 'package.json': JSON.stringify({ scripts: { dev: 'NODE_TLS_REJECT_UNAUTHORIZED=0 node server.mjs' } }) });
    expect(res.map((f) => f.severity)).toEqual(['medium', 'medium']);
  });

  it('safe: validation on, custom CA', async () => {
    expect(await one('NGB098', `import https from 'https';
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '1';
export const agent = new https.Agent({ rejectUnauthorized: true, ca: 'pem' });`)).toEqual([]);
  });

  it('false-positive regression: reading the variable, unrelated false properties', async () => {
    expect(await one('NGB098', `export const v = process.env.NODE_TLS_REJECT_UNAUTHORIZED === '0';
export const o = { reject: false, unauthorized: false };`)).toEqual([]);
  });
});
