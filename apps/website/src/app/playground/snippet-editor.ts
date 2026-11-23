import { ChangeDetectionStrategy, Component, DestroyRef, inject, signal } from '@angular/core';
import type { analyzeSnippet } from '../webmcp/analysis';

const example = "export const environment = {\n  clientSecret: 'BlueFern-84-Orbit-27'\n};";
@Component({
  selector: 'ngb-snippet-editor',
  changeDetection: ChangeDetectionStrategy.OnPush,
  styles: [`
    :host { display:block; margin-block:2rem }
    textarea { display:block; width:100%; font:inherit; font-family:monospace; color:inherit;
      background:var(--bg); border:1px solid var(--border); border-radius:.5rem; padding:1rem; resize:vertical }
    .actions { display:flex; flex-wrap:wrap; gap:.6rem; margin-block:1rem }
  `],
  template: `
    <article class="pg-panel">
      <h2>Analyze a TypeScript snippet</h2>
      <p>Check string literals for hardcoded credentials with NGB018. Run the CLI for template, configuration and project-wide checks.</p>
      <label for="snippet">TypeScript source</label>
      <textarea #editor id="snippet" rows="6" maxlength="32768" spellcheck="false" [value]="code()" (input)="edit(editor.value)"></textarea>
      <div class="actions">
        <button class="btn btn-primary" (click)="run()" [disabled]="busy() || !code().trim()">Analyze snippet</button>
        <button class="btn" (click)="edit(unsafe)">Load unsafe example</button>
        <button class="btn" (click)="edit(safe)">Load safe example</button>
        @if (result()?.status === 'ok') { <button class="btn" (click)="download()">Download HTML report</button> }
      </div>
      <div aria-live="polite">
        @if (busy()) { <p>Analyzing locally…</p> }
        @if (error()) { <p>{{ error() }}</p> }
        @if (result(); as r) {
          @if (r.status === 'ok') {
            <p>{{ r.summary.total }} findings · {{ r.rulesExecuted.join(', ') }} · {{ r.rulesSkipped.length }} rules skipped</p>
            @for (f of r.findings; track $index) {
              <div class="finding-card"><span [class]="'sev-badge sev-' + f.severity">{{ f.severity }}</span>
              <a [href]="f.documentation">{{ f.ruleId }}</a> · line {{ f.location.line }}, column {{ f.location.column }}
              <p>{{ f.message }}</p><p>{{ f.recommendation }}</p></div>
            }
          } @else { <p>{{ r.message }}</p> }
        }
      </div>
    </article>
  `,
})
export class SnippetEditor {
  readonly unsafe = example;
  readonly safe = "export const environment = { paymentsPublishableKey: 'pk_live_public' };";
  readonly code = signal(example);
  readonly result = signal<Awaited<ReturnType<typeof analyzeSnippet>> | undefined>(undefined);
  readonly busy = signal(false);
  readonly error = signal('');
  private controller?: AbortController;
  constructor() { inject(DestroyRef).onDestroy(() => this.controller?.abort()); }
  edit(code: string) {
    this.controller?.abort();
    this.code.set(code);
    this.result.set(undefined);
    this.error.set('');
    this.busy.set(false);
  }
  async run() {
    this.edit(this.code());
    const controller = this.controller = new AbortController();
    this.busy.set(true);
    try {
      const { analyzeSnippet } = await import('../webmcp/analysis');
      const result = await analyzeSnippet({ code: this.code() }, controller.signal);
      if (!controller.signal.aborted) this.result.set(result);
    } catch { if (!controller.signal.aborted) this.error.set('Could not load the local analyzer.'); }
    finally { if (!controller.signal.aborted) this.busy.set(false); }
  }
  async download() {
    const result = this.result();
    if (result?.status !== 'ok') return;
    try {
      const { generateReport } = await import('../webmcp/report');
      if (result !== this.result() || this.controller?.signal.aborted) return;
      const report = generateReport({ analysisId: result.analysisId });
      if (report.status !== 'ok') { this.error.set(report.message); return; }
      const url = URL.createObjectURL(new Blob([report.html], { type: report.mimeType }));
      try {
        const link = document.createElement('a');
        link.href = url;
        link.download = report.filename;
        link.click();
      } finally { setTimeout(() => URL.revokeObjectURL(url), 1000); }
    } catch { this.error.set('Could not create the report download.'); }
  }
}
