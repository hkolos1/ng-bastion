import { Component, inject } from '@angular/core';
import {
  DomSanitizer,
  SafeHtml,
} from '@angular/platform-browser';
import { ActivatedRoute } from '@angular/router';

@Component({
  selector: 'app-preview',
  template: `<article [innerHTML]="preview"></article>`,
})
export class PreviewComponent {
  private readonly sanitizer = inject(DomSanitizer);
  private readonly route = inject(ActivatedRoute);

  readonly preview: SafeHtml = this.render(
    this.route.snapshot.queryParamMap.get('draft') ?? '',
  );

  private render(markup: string): SafeHtml {
    const html = `<div class="draft">${markup}</div>`;
    return this.sanitizer.bypassSecurityTrustHtml(html);
  }
}
