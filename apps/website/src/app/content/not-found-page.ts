import { ChangeDetectionStrategy, Component, inject } from '@angular/core';
import { Meta } from '@angular/platform-browser';
import { RouterLink } from '@angular/router';
import { Seo } from '../core/seo.service';

@Component({
  selector: 'ngb-not-found-page',
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [RouterLink],
  template: `
    <section class="shell not-found">
      <p class="label">404</p>
      <h1>Page not found</h1>
      <p class="lead">This page is outside the walls. Try the <a routerLink="/docs">documentation</a>, the <a routerLink="/rules">rule reference</a> or search with <kbd>/</kbd>.</p>
    </section>
  `,
})
export class NotFoundPage {
  constructor() {
    inject(Seo).set({ title: 'Page not found | NgBastion', description: 'The requested page does not exist.', path: '/404' });
    inject(Meta).updateTag({ name: 'robots', content: 'noindex' });
  }
}
