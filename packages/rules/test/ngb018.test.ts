import { describe, expect, it } from 'vitest';
import { findings, one } from './helpers.js';
import { classifySecret, entropy, isPlaceholder } from '../src/shared/secrets.js';

// Secret-shaped values are assembled at runtime so no token-like literal is committed.
const stripeLive = ['sk', 'live', 'Zq8Lm3Np7Rt2Vx5Bc9Dk4Hj6'].join('_');
const stripeTest = ['sk', 'test', 'Zq8Lm3Np7Rt2Vx5Bc9Dk4Hj6'].join('_');
const publishable = ['pk', 'live', 'Zq8Lm3Np7Rt2Vx5Bc9Dk4Hj6'].join('_');
const github = ['ghp', 'Ab1Cd2Ef3Gh4Ij5Kl6Mn7Op8Qr9St0Uv1Wx2'].join('_');
const firebase = 'AI' + 'za' + 'SyD3fG7hJ2kL9mN4pQ8rS1tU6vW0xY5zA3b';
const randomSecret = 'q7W!z2' + 'Lp9#xV4m' + 'K8s$R1nT';

describe('NGB018 hardcoded frontend secrets', () => {
  it('reports a Stripe live secret key as critical and redacts it', async () => {
    const [f, ...rest] = await one('NGB018', `export const environment = { production: true, paymentsKey: '${stripeLive}' };`);
    expect(rest).toHaveLength(0);
    expect(f!.severity).toBe('critical');
    expect(f!.confidence).toBe('high');
    expect(f!.snippet).toBeUndefined();
    expect(JSON.stringify(f)).not.toContain(stripeLive);
    expect(f!.message).toContain('sk_l…(32 chars)');
  });

  it('reports test-mode keys with low severity and other known formats', async () => {
    const res = await one('NGB018', `export const a = '${stripeTest}';\nexport const b = '${github}';`);
    expect(res.map((f) => f.severity).sort()).toEqual(['critical', 'low']);
  });

  it('reports high-entropy values assigned to secret-named properties (heuristic)', async () => {
    const [f] = await one('NGB018', `export const cfg = { clientSecret: '${randomSecret}' };`);
    expect(f!.evidenceKind).toBe('heuristic');
    expect(f!.confidence).toBe('medium');
  });

  it('scans JSON configuration files and redacts values', async () => {
    const res = await findings('NGB018', {
      'src/app/a.ts': 'export const x = 1;',
      'src/assets/config.json': JSON.stringify({ api: { url: '/api', apiSecret: randomSecret } }, null, 2),
      'package.json': JSON.stringify({ name: 'x', secret: randomSecret }),
    });
    expect(res).toHaveLength(1);
    expect(res[0]!.location.file).toBe('src/assets/config.json');
    expect(res[0]!.location.line).toBe(4);
    expect(JSON.stringify(res[0])).not.toContain(randomSecret);
  });

  it('does not report publishable keys, Firebase browser keys, client IDs or placeholders', async () => {
    expect(await one('NGB018', `export const environment = {
  stripePublishableKey: '${publishable}',
  firebase: { apiKey: '${firebase}', appId: '1:1234:web:abcdef' },
  oauthClientId: 'Qz8xLm3Np7Rt2Vx5Bc9Dk4Hj',
  clientSecret: 'your-client-secret-here',
  password: '\${PASSWORD}',
  apiSecret: 'xxxxxxxxxxxxxxxxxxxxxxxx',
};`)).toEqual([]);
  });

  it('false-positive regression: low-entropy or sentence values under secret names are ignored', async () => {
    expect(await one('NGB018', `export const labels = { password: 'Enter your password please', resetSecret: 'aaaaaaaaaabbbbbbbbbb' };`)).toEqual([]);
  });

  it('helpers: entropy and placeholders', () => {
    expect(entropy('aaaa')).toBe(0);
    expect(isPlaceholder('<YOUR_KEY>')).toBe(true);
    expect(classifySecret(publishable)).toBeUndefined();
  });
});
