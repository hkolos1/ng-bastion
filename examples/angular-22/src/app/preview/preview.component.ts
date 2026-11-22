import { Component, ElementRef, computed, inject, signal } from '@angular/core';
import { DomSanitizer, SafeHtml } from '@angular/platform-browser';
import { toSignal } from '@angular/core/rxjs-interop';
import { ActivatedRoute } from '@angular/router';
import { map } from 'rxjs';
import { ContentService } from './content.service';

@Component({
  selector: 'app-preview',
  template: `<section [innerHTML]="trusted"></section><div #banner></div>`,
})
export class PreviewComponent {
  private readonly sanitizer = inject(DomSanitizer);
  private readonly content = inject(ContentService);
  private readonly host = inject<ElementRef<HTMLElement>>(ElementRef);
  private readonly route = inject(ActivatedRoute);

  /** NGB001: query parameter → service → bypassSecurityTrustHtml (cross-file). */
  readonly trusted: SafeHtml = this.sanitizer.bypassSecurityTrustHtml(this.content.previewHtml());

  /** Signals + RxJS: fragment → map() → toSignal() → computed(). */
  private readonly fragment = toSignal(this.route.fragment.pipe(map((f) => f ?? '')), { initialValue: '' });
  private readonly banner = computed(() => `<strong>${this.fragment()}</strong>`);
  readonly title = signal('Preview');

  render(): void {
    // NGB003: raw DOM sink fed by the computed signal.
    this.host.nativeElement.innerHTML = this.banner();
    // Safe: textContent never parses HTML.
    this.host.nativeElement.textContent = this.title();
  }
}
