import { Injectable, TransferState, inject, makeStateKey } from '@angular/core';
import { HttpClient } from '@angular/common/http';

interface Profile {
  email: string;
  sessionToken: string;
}

const PROFILE_KEY = makeStateKey<Profile>('profile');

@Injectable({ providedIn: 'root' })
export class ProfileResolver {
  private readonly http = inject(HttpClient);
  private readonly state = inject(TransferState);

  /** NGB020: per-user profile with a session token embedded in the server-rendered HTML. */
  load(): void {
    this.http.get<Profile>('/api/me').subscribe((profile) => this.state.set(PROFILE_KEY, profile));
  }
}
