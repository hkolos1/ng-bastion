import { ChangeDetectionStrategy, Component, effect, inject, input } from '@angular/core';
import { Seo } from '../core/seo.service';
import type { PageData } from '../core/content';
import { DocsShell } from '../layout/docs-shell';
import { RenderedContent } from '../content/rendered-content';
import { RuleExplorer } from './rule-explorer';

/** `/rules`: the interactive explorer above the generated catalog. */
@Component({
  selector: 'ngb-rules-index-page',
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [DocsShell, RenderedContent, RuleExplorer],
  template: `
    <ngb-docs-shell [slug]="page().slug" [title]="page().title" [section]="page().section" [headings]="page().headings">
      <p class="lead">{{ page().description }}</p>
      <ngb-rule-explorer />
      <ngb-rendered-content [blocks]="page().blocks" [slug]="page().slug" />
    </ngb-docs-shell>
  `,
})
export class RulesIndexPage {
  readonly page = input.required<PageData>();
  private readonly seo = inject(Seo);

  constructor() {
    effect(() => {
      const p = this.page();
      this.seo.set({ title: `${p.title} | NgBastion`, description: p.description, path: `/${p.slug}` });
    });
  }
}
