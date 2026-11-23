import { describe, expect, it } from 'vitest';
import { findings, one } from './helpers.js';

const IMP = `import { CanActivateFn, CanMatchFn, ActivatedRouteSnapshot, Routes } from '@angular/router';\nimport { inject } from '@angular/core';\n`;

describe('NGB022 authorization decision from user-controllable state', () => {
  it('reports a guard that trusts a role from localStorage', async () => {
    const res = await one('NGB022', `${IMP}export const adminGuard: CanActivateFn = () => localStorage.getItem('role') === 'admin';`);
    expect(res).toHaveLength(1);
    expect(res[0]!.message).toMatch(/role/);
    expect(res[0]!.evidenceKind).toBe('dataflow');
  });

  it('reports a query-parameter admin flag in a guard listed in a route array', async () => {
    const res = await one('NGB022', `${IMP}export const routes: Routes = [{ path: 'admin', canActivate: [(route: ActivatedRouteSnapshot) => {
  if (route.queryParams['isAdmin'] === 'true') return true;
  return false;
}] }];`);
    expect(res).toHaveLength(1);
  });

  it('follows a service method used by a guard class', async () => {
    const res = await findings('NGB022', {
      'src/app/perm.ts': `export class PermService { roles(): string[] { return JSON.parse(sessionStorage.getItem('permissions') ?? '[]'); } }`,
      'src/app/guard.ts': `import { CanActivate } from '@angular/router';\nimport { PermService } from './perm';\nexport class G implements CanActivate { constructor(private p: PermService) {} canActivate() { return this.p.roles().includes('editor'); } }`,
    });
    expect(res).toHaveLength(1);
  });

  it('safe: roles from a server response and token presence checks are not reported', async () => {
    expect(await one('NGB022', `${IMP}import { HttpClient } from '@angular/common/http';
import { map } from 'rxjs';
export const g1: CanActivateFn = () => inject(HttpClient).get<{ roles: string[] }>('/api/me').pipe(map((me) => me.roles.includes('admin')));
export const g2: CanActivateFn = () => !!localStorage.getItem('access_token');`)).toEqual([]);
  });

  it('false-positive regression: non-guard functions reading roles from storage are ignored', async () => {
    expect(await one('NGB022', `export function showAdminMenu() { return localStorage.getItem('role') === 'admin'; }`)).toEqual([]);
  });
});
