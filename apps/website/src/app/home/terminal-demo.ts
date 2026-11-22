import { ChangeDetectionStrategy, Component, computed, input } from '@angular/core';
import type { Showcase } from './showcase';

/** Terminal rendering of real scan output; animation is CSS-only and respects reduced motion. */
@Component({
  selector: 'ngb-terminal-demo',
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <figure class="hero-demo">
      <div class="terminal" role="img" aria-labelledby="demo-caption">
        <div class="terminal-bar"><span aria-hidden="true">●●●</span><span>examples/vulnerable-showcase</span></div>
        <div class="terminal-body" aria-hidden="true">
          <div><span class="prompt">$</span> ngbastion scan</div>
          <div class="t-muted">NgBastion {{ data().version }} · 1 project · {{ data().files }} files · {{ data().templates }} templates</div>
          @for (f of data().featured; track f.ruleId; let i = $index) {
            <div class="reveal finding" [style.--i]="i">
              <div><span class="sev" [class]="'sev-' + f.severity">{{ pad(f.severity) }}</span>&ngsp;<strong>{{ f.ruleId }}</strong> {{ f.ruleName }} <span class="t-muted">confidence: {{ f.confidence }}</span></div>
              <div class="t-path">{{ f.location.file }}:{{ f.location.line }}:{{ f.location.column }}</div>
              <ol class="trace">
                @for (s of f.trace ?? []; track $index) {
                  <li [class]="'k-' + s.kind"><span class="k">{{ s.kind }}</span>&ngsp;<span class="t-path">{{ base(s.file) }}:{{ s.line }}</span> {{ s.description }}</li>
                }
              </ol>
            </div>
          }
          <div class="reveal" [style.--i]="3"><strong>Summary:</strong> {{ data().total }} findings ({{ counts() }}) from {{ data().rulesTriggered }} rules</div>
          <div class="reveal" [style.--i]="4">Security gate (fail on {{ data().gate.failOn }}+): <span class="sev-high">{{ data().gate.failed ? 'FAILED' : 'passed' }}</span></div>
        </div>
      </div>
      <figcaption id="demo-caption">Real output of <code>ngbastion scan</code> on the repository's intentionally vulnerable showcase app, captured when this site was built. {{ data().featured.length }} of {{ data().total }} findings shown.</figcaption>
    </figure>
  `,
})
export class TerminalDemo {
  readonly data = input.required<Showcase>();
  protected readonly counts = computed(() => Object.entries(this.data().summary).map(([s, n]) => `${n} ${s}`).join(', '));
  protected pad(s: string): string {
    return s.toUpperCase().padEnd(8, ' ');
  }
  protected base(file: string): string {
    return file.split('/').pop() ?? file;
  }
}
