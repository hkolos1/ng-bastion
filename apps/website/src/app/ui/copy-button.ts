import { DOCUMENT } from '@angular/common';
import { ChangeDetectionStrategy, Component, DestroyRef, computed, inject, input, signal } from '@angular/core';

export type CopyState = 'idle' | 'copied' | 'error';

/** Copies `text` (the clean source, never UI chrome) and gives brief, accessible feedback. */
@Component({
  selector: 'ngb-copy-button',
  changeDetection: ChangeDetectionStrategy.OnPush,
  host: { class: 'copy' },
  template: `
    <button type="button" class="copy-btn" [attr.data-state]="state()" [attr.aria-label]="ariaLabel()"
            [attr.data-tooltip]="state() === 'copied' ? 'Copied' : state() === 'error' ? 'Copy failed' : 'Copy'" (click)="copy()">
      <svg class="i-copy" viewBox="0 0 24 24" width="15" height="15" aria-hidden="true"><rect x="8.5" y="8.5" width="12" height="12" rx="2.5" fill="none" stroke="currentColor" stroke-width="1.7"/><path d="M15.5 8.5V6a2.5 2.5 0 0 0-2.5-2.5H6A2.5 2.5 0 0 0 3.5 6v7A2.5 2.5 0 0 0 6 15.5h2.5" fill="none" stroke="currentColor" stroke-width="1.7"/></svg>
      <svg class="i-check" viewBox="0 0 24 24" width="15" height="15" aria-hidden="true"><path d="M5 12.5l4.5 4.5L19 7.5" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>
    </button>
    <span class="sr-only" aria-live="polite">{{ state() === 'copied' ? 'Copied to clipboard' : state() === 'error' ? 'Copy failed' : '' }}</span>
  `,
})
export class CopyButton {
  readonly text = input.required<string>();
  /** What is being copied, for the accessible name (e.g. "TypeScript snippet"). */
  readonly label = input('code');
  readonly state = signal<CopyState>('idle');
  protected readonly ariaLabel = computed(() => (this.state() === 'copied' ? `Copied ${this.label()}` : `Copy ${this.label()}`));
  private readonly document = inject(DOCUMENT);
  private timer: ReturnType<typeof setTimeout> | undefined;

  constructor() {
    inject(DestroyRef).onDestroy(() => clearTimeout(this.timer));
  }

  async copy(): Promise<void> {
    let ok: boolean;
    try {
      await navigator.clipboard.writeText(this.text());
      ok = true;
    } catch {
      ok = this.fallbackCopy();
    }
    this.state.set(ok ? 'copied' : 'error');
    clearTimeout(this.timer);
    this.timer = setTimeout(() => this.state.set('idle'), 1800);
  }

  /** For contexts without the async Clipboard API (e.g. insecure origins). */
  private fallbackCopy(): boolean {
    const doc = this.document;
    const area = doc.createElement('textarea');
    area.value = this.text();
    area.setAttribute('readonly', '');
    area.style.position = 'fixed';
    area.style.opacity = '0';
    doc.body.appendChild(area);
    area.select();
    try {
      return doc.execCommand('copy');
    } catch {
      return false;
    } finally {
      area.remove();
    }
  }
}
