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
          <a class="icon-btn" href="https://github.com/hkolos1/ng-bastion" target="_blank" rel="noopener"
             aria-label="NgBastion on GitHub" title="NgBastion on GitHub">
            <svg viewBox="0 0 16 16" width="16" height="16" aria-hidden="true"><path fill="currentColor" d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0 0 16 8c0-4.42-3.58-8-8-8Z"/></svg>
          </a>
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
