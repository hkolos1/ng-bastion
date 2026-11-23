import { ChangeDetectionStrategy, Component, inject } from '@angular/core';
import { RouterLink, RouterLinkActive } from '@angular/router';
import { ThemeService } from '../core/theme.service';
import { SearchDialog } from '../search/search-dialog';
import { SHOWCASE } from '../home/showcase';

@Component({
  selector: 'ngb-site-header',
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [RouterLink, RouterLinkActive, SearchDialog],
  template: `
    <header class="site-header">
      <div class="shell site-header-inner">
        <a class="brand" routerLink="/" aria-label="NgBastion home">
          <img class="only-dark" src="/brand/logo-mark-dark.svg" alt="" width="40" height="40" />
          <img class="only-light" src="/brand/logo-mark-light.svg" alt="" width="40" height="40" />
          <span>NgBastion</span>
        </a>
        <nav class="main-nav" aria-label="Main">
          <ul>
            @for (link of links; track link.href) {
              <li><a [routerLink]="link.href" routerLinkActive="current" ariaCurrentWhenActive="page">{{ link.label }}</a></li>
            }
          </ul>
        </nav>
        <div class="header-actions">
          <span class="version-pill" title="Latest release on npm">v{{ version }}</span>
          <ngb-search-dialog />
          <button class="icon-btn" type="button" (click)="theme.toggle()"
                  aria-label="Toggle color theme">
            <svg class="only-dark" viewBox="0 0 24 24" width="16" height="16" aria-hidden="true"><circle cx="12" cy="12" r="4" fill="none" stroke="currentColor" stroke-width="1.8"/><path stroke="currentColor" stroke-width="1.8" stroke-linecap="round" d="M12 2.5v2M12 19.5v2M2.5 12h2M19.5 12h2M5.3 5.3l1.4 1.4M17.3 17.3l1.4 1.4M5.3 18.7l1.4-1.4M17.3 6.7l1.4-1.4"/></svg>
            <svg class="only-light" viewBox="0 0 24 24" width="16" height="16" aria-hidden="true"><path fill="none" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round" d="M20 14.5A8 8 0 0 1 9.5 4a8 8 0 1 0 10.5 10.5Z"/></svg>
          </button>
        </div>
      </div>
    </header>
  `,
})
export class SiteHeader {
  protected readonly theme = inject(ThemeService);
  protected readonly version = SHOWCASE.version;
  protected readonly links = [
    { href: '/docs', label: 'Docs' },
    { href: '/rules', label: 'Rules' },
    { href: '/playground', label: 'Playground' },
    { href: '/changelog', label: 'Changelog' },
  ];
}
