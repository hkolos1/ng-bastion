import { ChangeDetectionStrategy, Component, computed, input, signal } from '@angular/core';
import { RouterLink, RouterLinkActive } from '@angular/router';
import { NAV, neighbours, type Heading } from '../core/content';

/** Documentation layout: sidebar navigation, article slot, on-this-page TOC and prev/next links. */
@Component({
  selector: 'ngb-docs-shell',
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [RouterLink, RouterLinkActive],
  template: `
    <div class="docs">
      <nav class="docs-nav" aria-label="Documentation" [class.open]="menuOpen()">
        <button type="button" class="docs-nav-toggle" (click)="menuOpen.set(!menuOpen())" [attr.aria-expanded]="menuOpen()">
          {{ menuOpen() ? 'Close menu' : 'Documentation menu' }}
        </button>
        @for (group of groups; track group.label) {
          <div class="nav-group">
            @if (group.label === 'Security rules') {
              <details [open]="slug().startsWith('rules')">
                <summary class="nav-title">{{ group.label }}</summary>
                <ul>
                  @for (item of group.items; track item.slug) {
                    <li><a [routerLink]="'/' + item.slug" routerLinkActive="current" [routerLinkActiveOptions]="{ exact: true }" ariaCurrentWhenActive="page">{{ item.label }}</a></li>
                  }
                </ul>
              </details>
            } @else {
              <h2 class="nav-title">{{ group.label }}</h2>
              <ul>
                @for (item of group.items; track item.slug) {
                  <li><a [routerLink]="'/' + item.slug" routerLinkActive="current" [routerLinkActiveOptions]="{ exact: true }" ariaCurrentWhenActive="page">{{ item.label }}</a></li>
                }
              </ul>
            }
          </div>
        }
      </nav>

      <article class="docs-main">
        <p class="eyebrow">{{ section() }}</p>
        <h1>{{ title() }}</h1>
        <ng-content />
        <nav class="pager" aria-label="Previous and next page">
          @if (pager().prev; as prev) {
            <a class="pager-prev" [routerLink]="'/' + prev.slug"><span>Previous</span>{{ prev.label }}</a>
          }
          @if (pager().next; as next) {
            <a class="pager-next" [routerLink]="'/' + next.slug"><span>Next</span>{{ next.label }}</a>
          }
        </nav>
      </article>

      @if (headings().length) {
        <aside class="toc" aria-labelledby="toc-h">
          <h2 id="toc-h" class="nav-title">On this page</h2>
          <ul>
            @for (h of headings(); track h.id) {
              <li [class.toc-sub]="h.depth === 3"><a [routerLink]="'/' + slug()" [fragment]="h.id">{{ h.text }}</a></li>
            }
          </ul>
        </aside>
      }
    </div>
  `,
})
export class DocsShell {
  readonly slug = input.required<string>();
  readonly title = input.required<string>();
  readonly section = input('Documentation');
  readonly headings = input<Heading[]>([]);
  protected readonly groups = NAV.groups;
  protected readonly menuOpen = signal(false);
  protected readonly pager = computed(() => neighbours(this.slug()));
}
