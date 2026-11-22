import { Component, input, linkedSignal, output } from '@angular/core';

/** Modern template syntax (@let, @switch, @defer, template literals) plus iframe checks. */
@Component({
  selector: 'app-embed',
  template: `
    @let label = 'Widget ' + kind();
    @switch (kind()) {
      @case ('video') { <span [title]="label">{{ label }}</span> }
      @default { <span>other</span> }
    }
    @defer (on idle) {
      <iframe [src]="url()" sandbox="allow-scripts allow-same-origin" title="embed"></iframe>
    } @placeholder {
      <p>loading…</p>
    }
    <iframe src="/static/terms.html" sandbox="" title="terms"></iframe>
    <p [attr.aria-label]="\`Embed of \${kind()}\`">{{ count() ** 2 }}</p>
  `,
})
export class EmbedComponent {
  readonly kind = input('video');
  readonly url = input.required<string>();
  readonly count = linkedSignal(() => this.kind().length);
  readonly closed = output<void>();
}
