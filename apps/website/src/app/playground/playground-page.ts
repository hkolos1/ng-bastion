import { ChangeDetectionStrategy, Component, computed, inject, signal } from '@angular/core';
import { RouterLink } from '@angular/router';
import { Seo } from '../core/seo.service';
import { CodeBlock } from '../ui/code-block';
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
  imports: [RouterLink, CodeBlock],
  template: `
    <section class="shell pg">
      <div class="pg-head">
        <p class="label">Playground</p>
        <h1>See a finding, then its fix.</h1>
        <p class="lead">Three Angular examples, each in an unsafe and a safer variant, with the findings NgBastion reported for them.</p>
      </div>
      <p class="notice" role="note"><strong>Demonstration:</strong>&ngsp;results were produced by NgBastion at build time for these fixtures; this page does not scan arbitrary input.</p>

      <div class="controls">
        <fieldset class="control">
          <legend class="label">Example</legend>
          <div class="segmented">
            @for (ex of data.examples; track ex.id) {
              <label><input type="radio" name="example" [value]="ex.id" [checked]="ex.id === exampleId()" (click)="exampleId.set(ex.id)" /><span>{{ ex.title }}</span></label>
            }
          </div>
        </fieldset>
        <fieldset class="control">
          <legend class="label">Variant</legend>
          <div class="segmented">
            <label><input type="radio" name="variant" value="unsafe" [checked]="variant() === 'unsafe'" (click)="variant.set('unsafe')" /><span>Unsafe</span></label>
            <label><input type="radio" name="variant" value="safe" [checked]="variant() === 'safe'" (click)="variant.set('safe')" /><span>Safe</span></label>
          </div>
        </fieldset>
      </div>

      <article class="pg-panel" aria-live="polite">
        <h2>{{ example().title }}: {{ variant() }} variant</h2>
        <p class="blurb">{{ variant() === 'unsafe' ? example().blurb : 'The same feature written with the safer pattern.' }}</p>
        <div class="cols">
          <div>
            @for (file of current().files; track file.name) {
              <ngb-code-block [snippet]="file" [filename]="file.name" [lineNumbers]="true" [highlight]="hits(file.name)" />
            }
          </div>
          <div class="results">
            <div class="results-head">
              <h3>{{ current().findings.length === 0 ? 'No findings' : current().findings.length + ' finding' + (current().findings.length > 1 ? 's' : '') }}</h3>
              <span class="label">scanned at build time</span>
            </div>
            @for (f of current().findings; track f.ruleId + f.location.line) {
              <div class="finding-card">
                <p class="head"><span class="sev-badge" [class]="'sev-badge sev-' + f.severity">{{ f.severity }}</span>&ngsp;<a [routerLink]="'/rules/' + f.ruleId.toLowerCase()">{{ f.ruleId }}</a>&ngsp;<span class="name">{{ f.ruleName }}</span></p>
                <p class="meta">confidence {{ f.confidence }} · {{ f.evidenceKind }} · line {{ f.location.line }}</p>
                <p class="msg">{{ f.message }}</p>
                @if (f.trace?.length) {
                  <ol class="trace" aria-label="Source to sink trace">
                    @for (s of f.trace; track $index) {
                      <li [class]="'k-' + s.kind"><span class="k">{{ s.kind }}</span><span><span class="at">line {{ s.line }}</span><span class="d">{{ s.description }}</span></span></li>
                    }
                  </ol>
                }
                <details>
                  <summary>Why it matters and how to fix it</summary>
                  <p>{{ why(f) }}</p>
                  <p><strong>Fix:</strong>&ngsp;{{ data.rules[f.ruleId]?.remediation }}</p>
                </details>
              </div>
            } @empty {
              <p class="empty-state">NgBastion found none of the patterns it models in this variant. That is evidence about these rules only, not proof that the code is secure.</p>
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

  protected hits(file: string): Set<number> {
    return this.hitCache().get(file) ?? new Set();
  }
  protected why(f: PgFinding): string {
    return firstSentence(this.data.rules[f.ruleId]?.rationale ?? '');
  }
}
