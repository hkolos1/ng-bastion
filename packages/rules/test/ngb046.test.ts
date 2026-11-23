import { describe, expect, it } from 'vitest';
import { one } from './helpers.js';

describe('NGB046 insecure randomness for security values', () => {
  it('reports Math.random() for OAuth state, tokens and storage keys', async () => {
    const res = await one('NGB046', `export function login() {
  const state = Math.random().toString(36).substring(2);
  sessionStorage.setItem('csrf_token', String(Math.floor(Math.random() * 1e9)));
  return state;
}`);
    expect(res).toHaveLength(2);
    expect(res.every((r) => r.confidence === 'high')).toBe(true);
  });

  it('reports via the enclosing function name (medium)', async () => {
    const res = await one('NGB046', `export function generateResetCode(): string { return Array.from({ length: 6 }, () => Math.floor(Math.random() * 10)).join(''); }`);
    expect(res).toHaveLength(1);
    expect(res[0]!.confidence).toBe('medium');
  });

  it('safe: crypto.getRandomValues and non-security uses', async () => {
    expect(await one('NGB046', `export function f(items: string[]) {
  const nonce = crypto.getRandomValues(new Uint8Array(16));
  const delay = Math.random() * 1000;
  const color = '#' + Math.floor(Math.random() * 0xffffff).toString(16);
  const shuffled = items.sort(() => Math.random() - 0.5);
  const requestId = Math.random().toString(36);
  return [nonce, delay, color, shuffled, requestId];
}`)).toEqual([]);
  });

  it('false-positive regression: UI words next to security words and local Math shadows', async () => {
    expect(await one('NGB046', `export function animationState() { return Math.random() > 0.5 ? 'open' : 'closed'; }
export function g() { const Math = { random: () => 4 }; const token = Math.random(); return token; }`)).toEqual([]);
  });
});
