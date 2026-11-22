import type { ElementRef} from '@angular/core';
import { ChangeDetectionStrategy, Component, computed, effect, inject, signal, viewChild } from '@angular/core';
import { Router } from '@angular/router';
import { searchIndex, type SearchEntry } from './search';

/** Site search. The index (generated at build time) is loaded lazily on first open. */
@Component({
  selector: 'ngb-search-dialog',
  changeDetection: ChangeDetectionStrategy.OnPush,
  host: { '(document:keydown)': 'onKey($event)' },
  template: `
    <button type="button" class="search-trigger" (click)="open()" aria-haspopup="dialog">
      <svg viewBox="0 0 24 24" width="16" height="16" aria-hidden="true"><path fill="currentColor" d="M10 3a7 7 0 1 0 4.2 12.6l4.6 4.6 1.4-1.4-4.6-4.6A7 7 0 0 0 10 3Zm0 2a5 5 0 1 1 0 10 5 5 0 0 1 0-10Z"/></svg>
      <span>Search</span><kbd>/</kbd>
    </button>
    <dialog #dialog class="search-dialog" aria-label="Search the documentation" (close)="query.set('')" (click)="backdrop($event)">
      <div class="search-panel">
        <input #input type="search" placeholder="Search docs and rules…" aria-label="Search" autocomplete="off"
               [value]="query()" (input)="query.set(input.value)" (keydown)="nav($event)" />
        @if (loading()) {
          <p class="search-empty">Loading index…</p>
        } @else if (query().trim().length > 1 && !hits().length) {
          <p class="search-empty">No results for “{{ query() }}”.</p>
        }
        <ul class="search-results" role="listbox">
          @for (hit of hits(); track hit.slug; let i = $index) {
            <li role="option" [attr.aria-selected]="i === active()">
              <a [href]="'/' + hit.slug + '/'" (click)="go($event, hit.slug)" [class.active]="i === active()">
                <span class="hit-title">{{ hit.title }}</span>
                <span class="hit-section">{{ hit.section }}</span>
                <span class="hit-snippet">{{ hit.snippet }}</span>
              </a>
            </li>
          }
        </ul>
        <p class="search-foot">↑↓ to move · Enter to open · Esc to close</p>
      </div>
    </dialog>
  `,
})
export class SearchDialog {
  private readonly router = inject(Router);
  private readonly dialog = viewChild.required<ElementRef<HTMLDialogElement>>('dialog');
  private readonly input = viewChild.required<ElementRef<HTMLInputElement>>('input');
  private readonly index = signal<SearchEntry[] | null>(null);
  readonly loading = signal(false);
  readonly query = signal('');
  readonly active = signal(0);
  readonly hits = computed(() => searchIndex(this.index() ?? [], this.query()));

  constructor() {
    effect(() => {
      this.hits();
      this.active.set(0);
    });
  }

  async open(): Promise<void> {
    this.dialog().nativeElement.showModal();
    this.input().nativeElement.focus();
    if (!this.index() && !this.loading()) {
      this.loading.set(true);
      const mod = await import('../../generated/search.json');
      this.index.set(mod.default as SearchEntry[]);
      this.loading.set(false);
    }
  }

  onKey(e: KeyboardEvent): void {
    const typing = e.target instanceof HTMLElement && (e.target.isContentEditable || ['INPUT', 'TEXTAREA', 'SELECT'].includes(e.target.tagName));
    if (!typing && (e.key === '/' || (e.key === 'k' && (e.metaKey || e.ctrlKey)))) {
      e.preventDefault();
      void this.open();
    }
  }

  nav(e: KeyboardEvent): void {
    const n = this.hits().length;
    if (!n) return;
    if (e.key === 'ArrowDown') this.active.update((i) => (i + 1) % n);
    else if (e.key === 'ArrowUp') this.active.update((i) => (i - 1 + n) % n);
    else if (e.key === 'Enter') this.go(e, this.hits()[this.active()]!.slug);
    else return;
    e.preventDefault();
  }

  go(e: Event, slug: string): void {
    e.preventDefault();
    this.dialog().nativeElement.close();
    void this.router.navigateByUrl(`/${slug}`);
  }

  backdrop(e: MouseEvent): void {
    if (e.target === this.dialog().nativeElement) this.dialog().nativeElement.close();
  }
}
