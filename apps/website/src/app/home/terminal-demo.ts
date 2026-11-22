import { ChangeDetectionStrategy, Component, computed, input, signal } from '@angular/core';
import type { Showcase } from './showcase';

/**
 * Real `ngbastion scan` output (captured at build time). One finding is shown at a time so the
 * source → sink trace stays readable; tabs switch between the featured findings.
 */
@Component({
  selector: 'ngb-terminal-demo',
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <figure class="hero-demo">
      <div class="terminal">
        <div class="terminal-bar">
          <span class="dots" aria-hidden="true"><i></i><i></i><i></i></span>
          <span>examples/vulnerable-showcase</span>
          <span>{{ data().files }} files</span>
        </div>
        <div class="terminal-body">
          <div class="terminal-cmd"><span class="prompt" aria-hidden="true">$</span>ngbastion scan</div>
          <div class="terminal-meta">NgBastion {{ data().version }} · {{ data().total }} findings from {{ data().rulesTriggered }} rules</div>

          <div class="terminal-tabs" role="tablist" aria-label="Featured findings">
            @for (f of data().featured; track f.ruleId; let i = $index) {
              <button type="button" role="tab" [id]="'demo-tab-' + i" [attr.aria-selected]="i === selected()"
                      [attr.aria-controls]="'demo-panel'" [attr.tabindex]="i === selected() ? 0 : -1"
                      (click)="selected.set(i)" (keydown)="onKey($event)">{{ f.ruleId }}</button>
            }
          </div>

          @if (finding(); as f) {
            <div class="demo-finding" id="demo-panel" role="tabpanel" [attr.aria-labelledby]="'demo-tab-' + selected()">
              <div class="finding-head reveal">
                <span class="sev-badge" [class]="'sev-badge sev-' + f.severity">{{ f.severity }}</span>
                <span class="rule">{{ f.ruleId }}</span>
                <span class="name">{{ f.ruleName }}</span>
                <span class="conf">confidence {{ f.confidence }}</span>
              </div>
              <div class="finding-loc reveal" [style.--i]="1">{{ f.location.file }}:{{ f.location.line }}:{{ f.location.column }}</div>
              <ol class="trace" aria-label="Source to sink trace">
                @for (s of f.trace ?? []; track $index; let i = $index) {
                  <li class="reveal" [class]="'reveal k-' + s.kind" [style.--i]="i + 2">
                    <span class="k">{{ s.kind }}</span>
                    <span><span class="at">{{ base(s.file) }}:{{ s.line }}</span><span class="d">{{ s.description }}</span></span>
                  </li>
                }
              </ol>
            </div>
          }

          <div class="terminal-summary">
            <span>{{ counts() }}</span>
            <span>gate (fail on {{ data().gate.failOn }}+): <span [class.failed]="data().gate.failed">{{ data().gate.failed ? 'FAILED' : 'passed' }}</span></span>
          </div>
        </div>
      </div>
      <figcaption class="terminal-caption">Real output of <code>ngbastion scan</code> on the repository's intentionally vulnerable showcase app, captured when this site was built. {{ data().featured.length }} of {{ data().total }} findings shown.</figcaption>
    </figure>
  `,
})
export class TerminalDemo {
  readonly data = input.required<Showcase>();
  readonly selected = signal(0);
  protected readonly finding = computed(() => this.data().featured[this.selected()]);
  protected readonly counts = computed(() => Object.entries(this.data().summary).map(([s, n]) => `${n} ${s}`).join(' · '));

  protected base(file: string): string {
    return file.split('/').pop() ?? file;
  }

  protected onKey(e: KeyboardEvent): void {
    const n = this.data().featured.length;
    if (e.key !== 'ArrowRight' && e.key !== 'ArrowLeft') return;
    e.preventDefault();
    this.selected.update((i) => (i + (e.key === 'ArrowRight' ? 1 : n - 1)) % n);
    const tab = (e.target as HTMLElement).parentElement?.children[this.selected()] as HTMLElement | undefined;
    tab?.focus();
  }
}
