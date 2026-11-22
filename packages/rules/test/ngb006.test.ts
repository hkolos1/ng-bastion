import { describe, expect, it } from 'vitest';
import { findings, one } from './helpers.js';

describe('NGB006 wildcard postMessage origin', () => {
  it('reports credentials sent to * with high confidence', async () => {
    const res = await one('NGB006', `export class A {
  token = '';
  send(frame: HTMLIFrameElement) { frame.contentWindow!.postMessage({ accessToken: this.token }, '*'); }
}`);
    expect(res).toHaveLength(1);
    expect(res[0]!.severity).toBe('high');
    expect(res[0]!.confidence).toBe('high');
    expect(res[0]!.message).toMatch(/credentials/);
  });

  it('resolves wildcard constants and { targetOrigin } options', async () => {
    const res = await one('NGB006', `const ANY = '*';
export function a(cardNumber: string) { window.parent.postMessage(cardNumber, ANY); }
export function b(password: string) { window.opener.postMessage({ password }, { targetOrigin: '*' }); }`);
    expect(res.map((f) => f.message)).toEqual([expect.stringMatching(/payment data/), expect.stringMatching(/credentials/)]);
  });

  it('reports non-sensitive wildcard payloads only as low/low', async () => {
    const [f] = await one('NGB006', `export function r(h: number) { window.parent.postMessage({ type: 'resize', height: h }, '*'); }`);
    expect(f!.severity).toBe('low');
    expect(f!.confidence).toBe('low');
  });

  it('does not report an explicit target origin (safe equivalent)', async () => {
    expect(await one('NGB006', `export function s(accessToken: string) { window.parent.postMessage({ accessToken }, 'https://app.example.com'); }`)).toEqual([]);
  });

  it('false-positive regression: Worker.postMessage and masked values', async () => {
    expect(await one('NGB006', `export function w(worker: Worker, password: string) { worker.postMessage(password); }`)).toEqual([]);
    const [f] = await one('NGB006', `declare function maskPan(v: string): string;
export function m(cardNumber: string) { window.parent.postMessage(maskPan(cardNumber), '*'); }`);
    expect(f!.severity).toBe('low');
  });

  it('detects sensitivity along a cross-file data flow (medium confidence)', async () => {
    const res = await findings('NGB006', {
      'src/auth.ts': `export class Auth { refreshToken = localStorage.getItem('rt') ?? ''; }`,
      'src/bridge.ts': `import { Auth } from './auth';
export class Bridge {
  constructor(private auth: Auth) {}
  share(frame: HTMLIFrameElement) { const value = this.auth.refreshToken; frame.contentWindow?.postMessage(value, '*'); }
}`,
    });
    expect(res).toHaveLength(1);
    expect(res[0]!.confidence).toBe('medium');
    expect(res[0]!.evidence.join(' ')).toMatch(/refreshToken/);
  });
});
