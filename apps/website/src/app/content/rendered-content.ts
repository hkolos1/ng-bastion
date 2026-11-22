import { ChangeDetectionStrategy, Component, inject, input } from '@angular/core';
import { Router } from '@angular/router';
import type { ContentBlock } from '../core/content';
import { CodeBlock } from '../ui/code-block';

/**
 * Renders build-time content. HTML blocks go through Angular's sanitizer ([innerHTML], no trust
 * bypass); headings are real Angular elements so they can carry `id`s for deep links, which the
 * sanitizer would strip. Same-site links become router navigations.
 */
@Component({
  selector: 'ngb-rendered-content',
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [CodeBlock],
  host: { class: 'prose', '(click)': 'onClick($event)' },
  template: `
    @for (block of blocks(); track $index) {
      @if (block.kind === 'heading') {
        @switch (block.depth) {
          @case (2) { <h2 [id]="block.id"><a class="anchor" [href]="'/' + slug() + '/#' + block.id" aria-hidden="true" tabindex="-1">#</a><span [innerHTML]="block.html"></span></h2> }
          @case (3) { <h3 [id]="block.id"><a class="anchor" [href]="'/' + slug() + '/#' + block.id" aria-hidden="true" tabindex="-1">#</a><span [innerHTML]="block.html"></span></h3> }
          @default { <h4 [id]="block.id"><span [innerHTML]="block.html"></span></h4> }
        }
      } @else if (block.kind === 'code') {
        <ngb-code-block [snippet]="block" />
      } @else {
        <div class="prose-block" [innerHTML]="block.html"></div>
      }
    }
  `,
})
export class RenderedContent {
  readonly blocks = input.required<ContentBlock[]>();
  readonly slug = input.required<string>();
  private readonly router = inject(Router);

  onClick(event: MouseEvent): void {
    if (event.defaultPrevented || event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
    const anchor = (event.target as Element | null)?.closest?.('a');
    const href = anchor?.getAttribute('href');
    if (!href || !href.startsWith('/') || href.startsWith('//') || href.startsWith('/brand/')) return;
    event.preventDefault();
    void this.router.navigateByUrl(href);
  }
}
