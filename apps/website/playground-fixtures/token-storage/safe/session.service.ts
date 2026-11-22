import { Injectable, inject, signal } from '@angular/core';
import { HttpClient } from '@angular/common/http';

interface LoginResponse {
  accessToken: string;
}

@Injectable({ providedIn: 'root' })
export class SessionService {
  private readonly http = inject(HttpClient);

  /**
   * Access token kept in memory only; the refresh token
   * lives in an HttpOnly cookie set by the server.
   */
  private readonly accessToken = signal<string | null>(null);

  login(email: string, password: string): void {
    this.http
      .post<LoginResponse>(
        '/api/login',
        { email, password },
        { withCredentials: true },
      )
      .subscribe((res) => {
        this.accessToken.set(res.accessToken);
        const domain = email.split('@')[1] ?? '';
        localStorage.setItem('last_login_email_domain', domain);
        console.log('logged in');
      });
  }
}
