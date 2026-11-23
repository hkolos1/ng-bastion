import { CanActivateFn } from '@angular/router';

// NGB022: the "admin" decision comes from storage the user can edit; only safe if the API enforces it too.
export const adminGuard: CanActivateFn = () => localStorage.getItem('role') === 'admin';
