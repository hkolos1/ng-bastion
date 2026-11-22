import { ChangeDetectionStrategy, Component, input } from '@angular/core';
import { RouterLink } from '@angular/router';
import type { Showcase } from './showcase';

/** One real finding, followed through the showcase source code from source to sink. */
@Component({
  selector: 'ngb-data-flow',
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [RouterLink],
  template: `
    <ol class="flow" aria-label="Data flow of {{ flow().ruleId }} from source to sink">
      @for (s of flow().steps; track $index; let first = $first; let last = $last) {
        <li class="flow-node" [class]="'flow-node k-' + s.kind" [style.--i]="$index">
          <div class="flow-marker" aria-hidden="true"></div>
          <div class="flow-card">
            <div class="flow-meta">
              <span class="flow-kind">{{ s.kind }}</span>
              <span class="flow-loc">{{ s.file }}:{{ s.line }}</span>
            </div>
            <pre class="flow-code"><code [innerHTML]="s.snippet.lines[0]"></code></pre>
            <p class="flow-desc">{{ s.description }}</p>
          </div>
        </li>
      }
    </ol>
    <p class="flow-verdict">
      <span class="sev-badge" [class]="'sev-badge sev-' + flow().severity">{{ flow().severity }}</span>
      <a [routerLink]="'/rules/' + flow().ruleId.toLowerCase()"><strong>{{ flow().ruleId }}</strong>&ngsp;{{ flow().ruleName }}</a>
      <span class="muted">confidence {{ flow().confidence }} · {{ flow().steps.length }} observed steps · {{ files() }} files</span>
    </p>
  `,
})
export class DataFlow {
  readonly data = input.required<Showcase>();
  protected flow() {
    return this.data().flow;
  }
  protected files(): number {
    return new Set(this.flow().steps.map((s) => s.file)).size;
  }
}
