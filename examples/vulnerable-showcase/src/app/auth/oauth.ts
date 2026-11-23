import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { ActivatedRoute } from '@angular/router';

const TOKEN_URL = 'https://login.example.com/oauth/token';

// NGB024: implicit flow, PKCE disabled, plain-HTTP identity provider allowed.
export const authConfig = {
  issuer: 'https://login.example.com',
  clientId: 'showcase-spa',
  responseType: 'id_token token',
  disablePKCE: true,
  requireHttps: false,
};

@Injectable({ providedIn: 'root' })
export class OAuthCallback {
  private readonly http = inject(HttpClient);
  private readonly route = inject(ActivatedRoute);

  complete(): void {
    // NGB023: the authorization code is redeemed without checking the state parameter.
    const code = this.route.snapshot.queryParamMap.get('code') ?? '';
    this.http.post<{ access_token: string }>(TOKEN_URL, { grant_type: 'authorization_code', code, client_id: 'showcase-spa' }).subscribe((res) => {
      // NGB025: session token written to a script-readable cookie (no HttpOnly, no Secure).
      document.cookie = `access_token=${res.access_token}; path=/`;
      // NGB028: token exposed to every script on the page.
      (window as unknown as Record<string, unknown>)['__AUTH__'] = { accessToken: res.access_token };
      // NGB029: window.name survives navigation to other sites.
      window.name = res.access_token;
    });
  }
}
