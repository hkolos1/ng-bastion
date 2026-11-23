import { ChangeDetectionStrategy, Component, computed, signal } from '@angular/core';
import { RouterLink } from '@angular/router';
import { FilterSelect } from './filter-select';
import rulesData from '../../generated/rules.json';

export interface RuleSummary {
  id: string;
  name: string;
  category: string;
  severity: string;
  cwe: string[];
  level: string;
  applies: string;
  summary: string;
}

const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info'];
const uniq = (xs: string[]) => [...new Set(xs)];

/** Client-side filter over the generated rule catalog; the unfiltered list is prerendered. */
@Component({
  selector: 'ngb-rule-explorer',
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [RouterLink, FilterSelect],
  template: `
    <section class="rule-explorer" aria-label="Rule explorer">
      <div class="rule-filters">
        <label class="rule-filter rule-filter-search">
          <span>Search</span>
          <input type="search" placeholder="ID, name or keyword" [value]="query()" (input)="query.set(value($event))" />
        </label>
        <ngb-filter-select label="Category" [options]="categories" [(value)]="category" />
        <ngb-filter-select label="Severity" [options]="severities" [(value)]="severity" />
        <ngb-filter-select label="Applies to" [options]="appliesTo" [(value)]="applies" />
        <ngb-filter-select label="CWE" [options]="cwes" [(value)]="cwe" />
        <ngb-filter-select label="Recommended" [options]="['error','warn']" [(value)]="level" [captions]="{ error: 'error (gates)', warn: 'warn (heuristic)' }" />
      </div>
      <p class="rule-count" aria-live="polite">
        {{ shown().length }} of {{ rules.length }} rules
        @if (filtered()) { <button type="button" class="rule-reset" (click)="reset()">Reset filters</button> }
      </p>
      <div class="table-wrap">
        <table class="rule-table">
          <thead><tr><th scope="col">ID</th><th scope="col">Rule</th><th scope="col">Severity</th><th scope="col">Applies to</th><th scope="col">CWE</th></tr></thead>
          <tbody>
            @for (r of shown(); track r.id) {
              <tr>
                <td><a [routerLink]="['/rules', r.id.toLowerCase()]" class="rule-id">{{ r.id }}</a></td>
                <td><a [routerLink]="['/rules', r.id.toLowerCase()]">{{ r.name }}</a><span class="rule-meta">{{ r.category }}@if (r.level === 'warn') { · warns in recommended }</span></td>
                <td><span class="sev-badge" [class]="'sev-' + r.severity">{{ r.severity }}</span></td>
                <td>{{ r.applies }}</td>
                <td class="rule-cwe">{{ r.cwe.join(', ') }}</td>
              </tr>
            } @empty {
              <tr><td colspan="5">No rule matches these filters.</td></tr>
            }
          </tbody>
        </table>
      </div>
    </section>
  `,
})
export class RuleExplorer {
  readonly rules = rulesData as RuleSummary[];
  readonly categories = uniq(this.rules.map((r) => r.category));
  readonly severities = SEVERITY_ORDER.filter((s) => this.rules.some((r) => r.severity === s));
  readonly appliesTo = uniq(this.rules.map((r) => r.applies)).sort();
  readonly cwes = uniq(this.rules.flatMap((r) => r.cwe)).sort((a, b) => Number(a.slice(4)) - Number(b.slice(4)));

  readonly query = signal('');
  readonly category = signal('');
  readonly severity = signal('');
  readonly applies = signal('');
  readonly cwe = signal('');
  readonly level = signal('');

  readonly filtered = computed(() => !!(this.query() || this.category() || this.severity() || this.applies() || this.cwe() || this.level()));
  readonly shown = computed(() => {
    const q = this.query().trim().toLowerCase();
    return this.rules.filter((r) =>
      (!q || `${r.id} ${r.name} ${r.summary} ${r.cwe.join(' ')}`.toLowerCase().includes(q))
      && (!this.category() || r.category === this.category())
      && (!this.severity() || r.severity === this.severity())
      && (!this.applies() || r.applies === this.applies())
      && (!this.cwe() || r.cwe.includes(this.cwe()))
      && (!this.level() || r.level === this.level()));
  });

  value(e: Event): string {
    return (e.target as HTMLInputElement | HTMLSelectElement).value;
  }

  reset(): void {
    for (const s of [this.query, this.category, this.severity, this.applies, this.cwe, this.level]) s.set('');
  }
}
