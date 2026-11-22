import { describe, expect, it } from 'vitest';
import { findings, one } from './helpers.js';

const HDR = `import { HttpInterceptorFn, HttpInterceptor, HttpRequest, HttpHandler } from '@angular/common/http';\nimport { inject } from '@angular/core';\ndeclare const environment: { apiUrl: string };\ndeclare function token(): string;\n`;

describe('NGB013 credential forwarding risk', () => {
  it('reports an unconditional Authorization header in a functional interceptor (high/high)', async () => {
    const res = await one('NGB013', `${HDR}export const auth: HttpInterceptorFn = (req, next) =>
  next(req.clone({ setHeaders: { Authorization: \`Bearer \${token()}\` } }));`);
    expect(res).toHaveLength(1);
    expect(res[0]!.confidence).toBe('high');
    expect(res[0]!.severity).toBe('high');
    expect(res[0]!.message).toMatch(/Authorization header/);
  });

  it('reports class interceptors using headers.set and withInterceptors-registered functions', async () => {
    const res = await findings('NGB013', {
      'src/app/a.ts': `${HDR}export class AuthInterceptor implements HttpInterceptor {
  intercept(req: HttpRequest<unknown>, next: HttpHandler) {
    return next.handle(req.clone({ headers: req.headers.set('X-Api-Key', token()) }));
  }
}`,
      'src/app/b.ts': `${HDR}export function keyInterceptor(req: any, next: any) { return next(req.clone({ setHeaders: { 'x-auth-token': token() } })); }`,
      'src/app/config.ts': `import { withInterceptors } from '@angular/common/http';\nimport { keyInterceptor } from './b';\nexport const p = withInterceptors([keyInterceptor]);`,
    });
    expect(res.map((f) => f.location.file).sort()).toEqual(['src/app/a.ts', 'src/app/b.ts']);
  });

  it('withCredentials-only is medium severity', async () => {
    const res = await one('NGB013', `${HDR}export const c: HttpInterceptorFn = (req, next) => next(req.clone({ withCredentials: true }));`);
    expect(res[0]!.severity).toBe('medium');
  });

  it('safe equivalent: destination checks (early return, variable, ternary, allowlist, relative)', async () => {
    expect(await one('NGB013', `${HDR}
export const a: HttpInterceptorFn = (req, next) => {
  if (!req.url.startsWith(environment.apiUrl)) return next(req);
  return next(req.clone({ setHeaders: { Authorization: token() } }));
};
export const b: HttpInterceptorFn = (req, next) => {
  const isApi = req.url.startsWith('https://api.example.com/');
  return next(isApi ? req.clone({ setHeaders: { Authorization: token() } }) : req);
};
const ALLOWED = ['https://api.example.com/'];
export const c: HttpInterceptorFn = (req, next) =>
  ALLOWED.some((u) => req.url.startsWith(u)) ? next(req.clone({ setHeaders: { Authorization: token() } })) : next(req);
export const d: HttpInterceptorFn = (req, next) => {
  if (req.url.startsWith('/') && !req.url.startsWith('//')) return next(req.clone({ setHeaders: { Authorization: token() } }));
  return next(req);
};`)).toEqual([]);
  });

  it('weak check → medium confidence', async () => {
    const res = await one('NGB013', `${HDR}export const a: HttpInterceptorFn = (req, next) =>
  req.url.includes('api') ? next(req.clone({ setHeaders: { Authorization: token() } })) : next(req);`);
    expect(res[0]!.confidence).toBe('medium');
  });

  it('false-positive regression: XSRF headers and non-interceptor clones are ignored', async () => {
    expect(await one('NGB013', `${HDR}
export const x: HttpInterceptorFn = (req, next) => next(req.clone({ setHeaders: { 'X-XSRF-TOKEN': token(), 'Accept-Language': 'en' } }));
const req = { clone: (o: unknown) => o };
req.clone({ setHeaders: { Authorization: token() } });`)).toEqual([]);
  });
});
