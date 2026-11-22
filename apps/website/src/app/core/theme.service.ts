import { DOCUMENT, isPlatformBrowser } from '@angular/common';
import { Injectable, PLATFORM_ID, computed, inject, signal } from '@angular/core';

export type Theme = 'dark' | 'light';
const KEY = 'ngbastion-theme';

/** Dark by default; follows the OS until the visitor picks a theme. Storage access is best-effort. */
@Injectable({ providedIn: 'root' })
export class ThemeService {
  private readonly document = inject(DOCUMENT);
  private readonly browser = isPlatformBrowser(inject(PLATFORM_ID));
  private readonly chosen = signal<Theme | null>(this.read());

  readonly theme = computed<Theme>(() => this.chosen() ?? this.systemTheme());

  toggle(): void {
    const next: Theme = this.theme() === 'dark' ? 'light' : 'dark';
    this.chosen.set(next);
    this.document.documentElement.dataset['theme'] = next;
    try {
      localStorage.setItem(KEY, next);
    } catch {
      /* private mode: the choice lasts for this page view */
    }
  }

  private read(): Theme | null {
    if (!this.browser) return null;
    const fromDom = this.document.documentElement.dataset['theme'];
    if (fromDom === 'light' || fromDom === 'dark') return fromDom;
    try {
      const v = localStorage.getItem(KEY);
      return v === 'light' || v === 'dark' ? v : null;
    } catch {
      return null;
    }
  }

  private systemTheme(): Theme {
    return this.browser && typeof matchMedia === 'function' && matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark';
  }
}
