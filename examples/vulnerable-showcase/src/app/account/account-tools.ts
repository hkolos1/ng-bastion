import { Injectable } from '@angular/core';

declare const analytics: { track(event: string, props: object): void };

@Injectable({ providedIn: 'root' })
export class AccountTools {
  accessToken = '';

  /** NGB066: a bearer token on the system clipboard. */
  copyToken(): Promise<void> {
    return navigator.clipboard.writeText(this.accessToken);
  }

  /** NGB067: the password ends up in a third-party analytics event. */
  trackSignup(form: { email: string; password: string; plan: string }): void {
    analytics.track('Signed Up', { plan: form.plan, password: form.password });
  }
}
