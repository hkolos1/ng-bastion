import { ChangeDetectionStrategy, Component, inject } from '@angular/core';
import { RouterLink, RouterLinkActive } from '@angular/router';
import { ThemeService } from '../core/theme.service';
import { SearchDialog } from '../search/search-dialog';

@Component({
  selector: 'ngb-site-header',
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [RouterLink, RouterLinkActive, SearchDialog],
  template: `
    <header class="site-header">
      <a class="brand" routerLink="/" aria-label="NgBastion home">
        <img class="brand-mark only-dark" src="/brand/logo-mark-dark.svg" alt="" width="32" height="32" />
        <img class="brand-mark only-light" src="/brand/logo-mark-light.svg" alt="" width="32" height="32" />
        <span>NgBastion</span>
      </a>
      <nav aria-label="Main">
        <ul>
          @for (link of links; track link.href) {
            <li><a [routerLink]="link.href" routerLinkActive="current" ariaCurrentWhenActive="page">{{ link.label }}</a></li>
          }
        </ul>
      </nav>
      <ngb-search-dialog />
      <button class="theme" type="button" (click)="theme.toggle()"
              [attr.aria-label]="theme.theme() === 'dark' ? 'Switch to light theme' : 'Switch to dark theme'">
        <svg viewBox="0 0 24 24" width="18" height="18" aria-hidden="true"><path fill="currentColor" d="M12 3a9 9 0 1 0 9 9 7 7 0 0 1-9-9Z"/></svg>
      </button>
    </header>
  `,
})
export class SiteHeader {
  protected readonly theme = inject(ThemeService);
  protected readonly links = [
    { href: '/docs', label: 'Docs' },
    { href: '/rules', label: 'Rules' },
    { href: '/playground', label: 'Playground' },
    { href: '/changelog', label: 'Changelog' },
  ];
}
