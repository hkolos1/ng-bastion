import { ChangeDetectionStrategy, Component, computed, input } from '@angular/core';
import { CopyButton } from './copy-button';

/** A build-time highlighted snippet (see scripts/generate.mjs `highlight()`). */
export interface CodeSnippet {
  lang: string;
  label: string;
  /** Clean source: what the copy button copies. */
  code: string;
  /** One HTML string per line (spans with classes only); rendered through Angular's sanitizer. */
  lines: string[];
}

const NO_NUMBERS = new Set(['sh', 'bash', 'shell', 'console', 'text', 'txt', '']);

/** The single code block used everywhere: docs, rule pages, landing page and playground. */
@Component({
  selector: 'ngb-code-block',
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [CopyButton],
  template: `
    <figure class="code-block" [class.numbered]="numbered()">
      <figcaption class="code-head">
        <span class="code-lang">{{ snippet().label }}</span>
        @if (filename()) {
          <span class="code-file">{{ filename() }}</span>
        }
        <ngb-copy-button [text]="snippet().code" [label]="(filename() || snippet().label) + ' snippet'" />
      </figcaption>
      <pre class="code-body" tabindex="0" [attr.aria-label]="(filename() || snippet().label) + ' code'"><code>@for (line of snippet().lines; track $index) {<span class="line" [class.hit]="highlight().has($index + 1)" [innerHTML]="line"></span>}</code></pre>
    </figure>
  `,
})
export class CodeBlock {
  readonly snippet = input.required<CodeSnippet>();
  readonly filename = input<string>();
  /** `auto`: numbered when longer than three lines and not a shell/text snippet. */
  readonly lineNumbers = input<boolean | 'auto'>('auto');
  readonly highlight = input<ReadonlySet<number>>(new Set());
  protected readonly numbered = computed(() => {
    const mode = this.lineNumbers();
    return mode === 'auto' ? this.snippet().lines.length > 3 && !NO_NUMBERS.has(this.snippet().lang) : mode;
  });
}
