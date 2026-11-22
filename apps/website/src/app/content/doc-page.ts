import { ChangeDetectionStrategy, Component, effect, inject, input } from '@angular/core';
import { Seo } from '../core/seo.service';
import type { PageData } from '../core/content';
import { DocsShell } from '../layout/docs-shell';
import { RenderedContent } from './rendered-content';

/** Any generated markdown page (docs, rules, changelog). `page` comes from the route resolver. */
@Component({
  selector: 'ngb-doc-page',
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [DocsShell, RenderedContent],
  template: `
    <ngb-docs-shell [slug]="page().slug" [title]="page().title" [section]="page().section" [headings]="page().headings">
      <p class="lead">{{ page().description }}</p>
      <ngb-rendered-content [blocks]="page().blocks" [slug]="page().slug" />
    </ngb-docs-shell>
  `,
})
export class DocPage {
  readonly page = input.required<PageData>();
  private readonly seo = inject(Seo);

  constructor() {
    effect(() => {
      const p = this.page();
      this.seo.set({ title: `${p.title} | NgBastion`, description: p.description, path: `/${p.slug}` });
    });
  }
}
