import { ChangeDetectionStrategy, Component, computed, inject, signal } from '@angular/core';
import { RouterLink } from '@angular/router';
import { Seo } from '../core/seo.service';
import { PLAYGROUND, type PgData, type PgFinding, type PgVariant } from './playground-data';

export type Variant = 'unsafe' | 'safe';

const firstSentence = (text: string) => /^(.+?[.!?])(\s|$)/.exec(text)?.[1] ?? text;

/** Highlighted lines: finding locations plus trace steps in the same file. */
export function hitLines(variant: PgVariant, file: string): Set<number> {
  const lines = new Set<number>();
  for (const f of variant.findings) {
    if (f.location.file.endsWith(file)) lines.add(f.location.line);
    for (const s of f.trace ?? []) if (s.file.endsWith(file)) lines.add(s.line);
  }
  return lines;
}

@Component({
  selector: 'ngb-playground-page',
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [RouterLink],
  template: `
    <section class="pg">
      <h1>Playground</h1>
      <p class="notice" role="note"><strong>Demonstration:</strong> results were produced by NgBastion at build time for these fixtures; this page does not scan arbitrary input.</p>

      <div class="controls">
        <fieldset>
          <legend>Example</legend>
          @for (ex of data.examples; track ex.id) {
            <label><input type="radio" name="example" [value]="ex.id" [checked]="ex.id === exampleId()" (click)="exampleId.set(ex.id)" /> {{ ex.title }}</label>
          }
        </fieldset>
        <fieldset>
          <legend>Variant</legend>
          <label><input type="radio" name="variant" value="unsafe" [checked]="variant() === 'unsafe'" (click)="variant.set('unsafe')" /> Unsafe</label>
          <label><input type="radio" name="variant" value="safe" [checked]="variant() === 'safe'" (click)="variant.set('safe')" /> Safe</label>
        </fieldset>
      </div>

      <article class="panel" aria-live="polite">
        <h2>{{ example().title }}: {{ variant() }} variant</h2>
        <p class="blurb">{{ variant() === 'unsafe' ? example().blurb : 'The same feature written with the safer pattern.' }}</p>
        <div class="cols">
          <div>
            @for (file of current().files; track file.name) {
              <figure class="code-figure">
                <figcaption>{{ file.name }}</figcaption>
                <pre><code>@for (line of lines(file.code); track $index) {<span class="ln" [class.hit]="hits(file.name).has($index + 1)"><span class="no" aria-hidden="true">{{ $index + 1 }}</span>{{ line }}
</span>}</code></pre>
              </figure>
            }
          </div>
          <div class="results">
            <h3>{{ current().findings.length === 0 ? 'No findings' : current().findings.length + ' finding' + (current().findings.length > 1 ? 's' : '') }}</h3>
            @for (f of current().findings; track f.ruleId + f.location.line) {
              <div class="finding">
                <p class="head"><span class="sev" [class]="'sev-' + f.severity">{{ f.severity }}</span>&ngsp;<a [routerLink]="'/rules/' + f.ruleId.toLowerCase()">{{ f.ruleId }}</a> {{ f.ruleName }}</p>
                <p class="meta">Confidence {{ f.confidence }}, {{ f.evidenceKind }} evidence, line {{ f.location.line }}</p>
                <p>{{ f.message }}</p>
                @if (f.trace?.length) {
                  <ol class="trace">
                    @for (s of f.trace; track $index) {
                      <li [class]="'k-' + s.kind"><span class="k">{{ s.kind }}</span>&ngsp;line {{ s.line }}: {{ s.description }}</li>
                    }
                  </ol>
                }
                <details>
                  <summary>Why it matters and how to fix it</summary>
                  <p>{{ why(f) }}</p>
                  <p><strong>Fix:</strong> {{ data.rules[f.ruleId]?.remediation }}</p>
                </details>
              </div>
            } @empty {
              <p class="muted">NgBastion found none of the patterns it models in this variant. That is evidence about these rules only, not proof that the code is secure.</p>
            }
          </div>
        </div>
      </article>
    </section>
  `,
})
export class PlaygroundPage {
  protected readonly data: PgData = PLAYGROUND;
  readonly exampleId = signal(PLAYGROUND.examples[0]!.id);
  readonly variant = signal<Variant>('unsafe');
  readonly example = computed(() => this.data.examples.find((e) => e.id === this.exampleId()) ?? this.data.examples[0]!);
  readonly current = computed(() => this.example().variants[this.variant()]);
  private readonly hitCache = computed(() => new Map(this.current().files.map((f) => [f.name, hitLines(this.current(), f.name)])));

  constructor() {
    inject(Seo).set({
      title: 'Playground | NgBastion',
      description: 'A minimal NgBastion demonstration: three Angular examples with unsafe and safe variants, and the findings NgBastion produced for them at build time.',
      path: '/playground',
    });
  }

  protected lines(code: string): string[] {
    return code.replace(/\n$/, '').split('\n');
  }
  protected hits(file: string): Set<number> {
    return this.hitCache().get(file) ?? new Set();
  }
  protected why(f: PgFinding): string {
    return firstSentence(this.data.rules[f.ruleId]?.rationale ?? '');
  }
}
