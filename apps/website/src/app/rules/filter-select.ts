import { ChangeDetectionStrategy, Component, ElementRef, computed, inject, input, model, signal } from '@angular/core';

@Component({
  selector: 'ngb-filter-select',
  changeDetection: ChangeDetectionStrategy.OnPush,
  host: { class: 'rule-filter', '(document:pointerdown)': 'outside($event)' },
  template: `
    <span [id]="id() + '-label'">{{ label() }}</span>
    <button type="button" role="combobox" aria-haspopup="listbox"
      [attr.aria-labelledby]="id() + '-label ' + id() + '-value'"
      [attr.aria-expanded]="open()" [attr.aria-controls]="id() + '-list'"
      [attr.aria-activedescendant]="open() ? id() + '-' + active() : null"
      (click)="toggle()" (keydown)="key($event)" (blur)="close()">
      <span [id]="id() + '-value'">{{ caption(value()) }}</span><span aria-hidden="true" class="filter-chevron"></span>
    </button>
    <div role="listbox" [hidden]="!open()" [id]="id() + '-list'" [attr.aria-labelledby]="id() + '-label'">
      @for (item of items(); track item; let i = $index) {
        <div role="option" [id]="id() + '-' + i" [attr.aria-selected]="item === value()"
          [class.active]="i === active()" (pointerdown)="$event.preventDefault()" (click)="choose(i)">
          <span class="filter-check" aria-hidden="true">{{ item === value() ? '✓' : '' }}</span>{{ caption(item) }}
        </div>
      }
    </div>
  `,
})
export class FilterSelect {
  readonly label = input.required<string>();
  readonly options = input.required<string[]>();
  readonly captions = input<Record<string, string>>({});
  readonly value = model('');
  readonly id = computed(() => 'rule-filter-' + this.label().toLowerCase().replaceAll(' ', '-'));
  readonly items = computed(() => ['', ...this.options()]);
  readonly open = signal(false);
  readonly active = signal(0);
  private readonly host = inject(ElementRef<HTMLElement>);
  private prefix = '';
  private lastKey = 0;

  caption(item: string) {
    if (!item) return 'All';
    const captions = this.captions();
    return Object.hasOwn(captions, item) ? captions[item] : item;
  }
  close() { this.open.set(false); this.prefix = ''; }
  outside(event: Event) { if (this.open() && !this.host.nativeElement.contains(event.target as Node)) this.close(); }
  toggle() {
    if (this.open()) this.close();
    else {
      this.active.set(Math.max(0, this.items().indexOf(this.value())));
      this.open.set(true);
      this.reveal();
    }
  }
  choose(index: number) { this.value.set(this.items()[index]); this.close(); }
  private reveal() {
    requestAnimationFrame(() => {
      if (this.open()) this.host.nativeElement.querySelectorAll('[role=option]')[this.active()]?.scrollIntoView({ block: 'nearest' });
    });
  }
  key(event: KeyboardEvent) {
    const key = event.key;
    if (key === 'Tab') { this.close(); return; }
    if (key === 'Escape') { this.close(); return; }
    if (event.ctrlKey || event.metaKey || event.altKey) return;
    if ([' ', 'Enter'].includes(key)) {
      event.preventDefault();
      if (this.open()) this.choose(this.active()); else this.toggle();
      return;
    }
    if (!['ArrowDown', 'ArrowUp', 'Home', 'End'].includes(key) && key.length !== 1) return;
    event.preventDefault();
    if (!this.open()) this.toggle();
    const last = this.items().length - 1;
    if (key === 'Home') this.active.set(0);
    else if (key === 'End') this.active.set(last);
    else if (key === 'ArrowDown') this.active.update(i => Math.min(last, i + 1));
    else if (key === 'ArrowUp') this.active.update(i => Math.max(0, i - 1));
    else {
      this.prefix = (Date.now() - this.lastKey < 600 ? this.prefix : '') + key.toLowerCase();
      this.lastKey = Date.now();
      const index = this.items().findIndex(item => this.caption(item).toLowerCase().startsWith(this.prefix));
      if (index >= 0) this.active.set(index);
    }
    this.reveal();
  }
}
