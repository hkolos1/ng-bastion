import { Component, inject } from '@angular/core';
import { ActivatedRoute } from '@angular/router';

@Component({
  selector: 'app-preview',
  // Angular sanitizes [innerHTML] bindings:
  // scripts and event handlers are stripped.
  template: `<article [innerHTML]="preview"></article>`,
})
export class PreviewComponent {
  private readonly route = inject(ActivatedRoute);

  private readonly draft =
    this.route.snapshot.queryParamMap.get('draft') ?? '';

  readonly preview = `<div class="draft">${this.draft}</div>`;
}
