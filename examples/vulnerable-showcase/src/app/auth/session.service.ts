import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Router } from '@angular/router';

interface LoginResponse {
  accessToken: string;
  refreshToken: string;
}

@Injectable({ providedIn: 'root' })
export class SessionService {
  private readonly http = inject(HttpClient);
  private readonly router = inject(Router);

  // NGB018: a private client secret shipped to every browser (synthetic value).
  private readonly clientSecret = 'q8Zr1vX4mT7kP2wN9cL5yB3hJ6fD0sGa';

  login(username: string, password: string): void {
    // NGB016: credentials written to the browser console.
    console.log('login attempt', { username, password });
    this.http.post<LoginResponse>('/api/login', { username, password, clientSecret: this.clientSecret }).subscribe((res) => {
      // NGB014: long-lived tokens in script-readable storage.
      localStorage.setItem('refresh_token', res.refreshToken);
      // NGB017: access token placed in a URL (logs, Referer, history).
      this.router.navigate(['/welcome'], { queryParams: { access_token: res.accessToken } });
    });
  }
}
