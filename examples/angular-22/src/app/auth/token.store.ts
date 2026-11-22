import { Injectable } from '@angular/core';

@Injectable({ providedIn: 'root' })
export class TokenStore {
  /** NGB014: long-lived token in script-readable persistent storage. */
  save(accessToken: string): void {
    localStorage.setItem('access_token', accessToken);
  }

  /** Not sensitive: UI preference. */
  saveTheme(theme: 'light' | 'dark'): void {
    localStorage.setItem('theme', theme);
  }
}
