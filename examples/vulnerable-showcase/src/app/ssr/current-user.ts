import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { tap } from 'rxjs';

/** NGB055: module scope is shared by every request the SSR server renders. */
let currentUser: unknown;

@Injectable({ providedIn: 'root' })
export class CurrentUserService {
  private readonly http = inject(HttpClient);

  load() {
    return this.http.get('/api/me').pipe(tap((user) => (currentUser = user)));
  }

  get user(): unknown {
    return currentUser;
  }
}
