import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';

interface LoginResponse {
  accessToken: string;
  refreshToken: string;
}

@Injectable({ providedIn: 'root' })
export class SessionService {
  private readonly http = inject(HttpClient);

  login(email: string, password: string): void {
    this.http
      .post<LoginResponse>('/api/login', { email, password })
      .subscribe((res) => {
        localStorage.setItem('refresh_token', res.refreshToken);
        console.log('logged in', res.accessToken);
      });
  }
}
