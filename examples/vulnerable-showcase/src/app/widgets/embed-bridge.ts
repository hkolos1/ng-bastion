import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { ActivatedRoute } from '@angular/router';
import { merge } from 'lodash-es';

/** Embeddable widget bridge: talks to whatever page hosts the app in an iframe. */
@Injectable({ providedIn: 'root' })
export class EmbedBridge {
  private readonly http = inject(HttpClient);
  private readonly route = inject(ActivatedRoute);
  private readonly settings: Record<string, unknown> = {};

  listen(sessionToken: string): void {
    window.addEventListener('message', (event: MessageEvent) => {
      // NGB034: replies to whatever origin sent the message, including the session token.
      (event.source as Window).postMessage({ sessionToken }, event.origin);
      // NGB035: the embedding page chooses which method of this service runs.
      (this as unknown as Record<string, (arg: unknown) => void>)[event.data.method](event.data.args);
      // NGB036: deep merge of a parsed message can write to Object.prototype.
      merge(this.settings, JSON.parse(event.data.settings));
    });
  }

  search(items: string[]): string[] {
    // NGB037: regex syntax from the URL (and catastrophic patterns) reaches RegExp.
    const q = this.route.snapshot.queryParamMap.get('q') ?? '';
    return items.filter((i) => new RegExp(q, 'i').test(i));
  }

  openPartner(url: string): void {
    // NGB033: the partner page can rewrite this tab through window.opener.
    window.open(url, '_blank');
  }

  async cacheAccount(): Promise<void> {
    // NGB031: the account response stays in CacheStorage after logout.
    const cache = await caches.open('api');
    await cache.add('/api/account');
  }

  weather(): void {
    // NGB039: the JSONP response executes as script in this origin.
    this.http.jsonp('https://api.weather.example/v1/today', 'callback').subscribe();
  }

  live(): WebSocket {
    // NGB040: realtime feed (with session cookies on the handshake) over plain ws://.
    return new WebSocket('ws://realtime.example.com/feed');
  }
}
