import { Injectable, inject } from '@angular/core';
import { HttpHeaders } from '@angular/common/http';
import { ActivatedRoute } from '@angular/router';
import { OAuthService } from 'angular-oauth2-oidc';

const ISSUER = 'https://id.example.com';

@Injectable({ providedIn: 'root' })
export class LegacyOidcService {
  private readonly oauth = inject(OAuthService);
  private readonly route = inject(ActivatedRoute);

  /** NGB057: hybrid sign-in asks for an id_token without a nonce. */
  signIn(state: string): void {
    location.assign(`${ISSUER}/authorize?client_id=portal&response_type=id_token%20token&redirect_uri=${encodeURIComponent(location.origin + '/cb')}&state=${state}`);
  }

  /** NGB060: the identity provider is told to deliver the tokens to a URL taken from the link. */
  configure(): void {
    this.oauth.configure({ issuer: ISSUER, clientId: 'portal', responseType: 'code', redirectUri: this.route.snapshot.queryParams['returnTo'] });
  }

  /** NGB058: the ID token is used as the API bearer token. */
  apiHeaders(): HttpHeaders {
    return new HttpHeaders().set('Authorization', `Bearer ${this.oauth.getIdToken()}`);
  }
}
