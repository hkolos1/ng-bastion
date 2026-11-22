import { describe, expect, it } from 'vitest';
import { NG, findings, one } from './helpers.js';

const cls = (body: string) => `${NG}
@Component({ selector: 'app-x', template: '<div [innerHTML]="content"></div>' })
export class X {
  private sanitizer = inject(DomSanitizer);
  private route = inject(ActivatedRoute);
  content: SafeHtml = '';
${body}
}`;

describe('NGB001 unsafe HTML trust bypass', () => {
  it('reports a query parameter reaching bypassSecurityTrustHtml (high confidence, trace + template evidence)', async () => {
    const [f, ...rest] = await one('NGB001', cls(`  ngOnInit() {
    const html = this.route.snapshot.queryParamMap.get('preview') ?? '';
    this.content = this.sanitizer.bypassSecurityTrustHtml(html);
  }`));
    expect(rest).toHaveLength(0);
    expect(f!.ruleId).toBe('NGB001');
    expect(f!.severity).toBe('high');
    expect(f!.confidence).toBe('high');
    expect(f!.evidenceKind).toBe('dataflow');
    expect(f!.trace!.map((s) => s.kind)).toEqual(['source', 'assignment', 'sink']);
    expect(f!.trace![0]!.description).toContain(`'preview'`);
    expect(f!.evidence.join('\n')).toMatch(/bound to <div \[innerHTML\]>/);
  });

  it('reports across files through a service and RxJS map()', async () => {
    const res = await findings('NGB001', {
      'src/app/msg.service.ts': `${NG}import { map } from 'rxjs';
export class MessageService {
  private http = inject(HttpClient);
  load() { return this.http.get<{ body: string }>('/api/message').pipe(map(r => r.body)); }
}`,
      'src/app/view.ts': `${NG}import { MessageService } from './msg.service';
export class View {
  html: SafeHtml = '';
  constructor(private svc: MessageService, private s: DomSanitizer) {}
  ngOnInit() { this.svc.load().subscribe(b => this.html = this.s.bypassSecurityTrustHtml(b)); }
}`,
    });
    expect(res).toHaveLength(1);
    expect(res[0]!.confidence).toBe('medium'); // HTTP responses are medium-trust sources
    expect(new Set(res[0]!.trace!.map((s) => s.file))).toEqual(new Set(['src/app/msg.service.ts', 'src/app/view.ts']));
  });

  it('does not report constant HTML', async () => {
    expect(await one('NGB001', cls(`  ok() { this.content = this.sanitizer.bypassSecurityTrustHtml('<b>Welcome</b>'); }`))).toEqual([]);
  });

  it('does not report sanitize-then-bypass (safe equivalent)', async () => {
    expect(await one('NGB001', `${NG}import DOMPurify from 'dompurify';
export class X {
  constructor(private s: DomSanitizer, private route: ActivatedRoute) {}
  a() { return this.s.bypassSecurityTrustHtml(DOMPurify.sanitize(this.route.snapshot.queryParams['h'])); }
}`)).toEqual([]);
  });

  it('reports bypass of an unresolved value only with low confidence', async () => {
    const res = await one('NGB001', cls(`  render(html: string) { this.content = this.sanitizer.bypassSecurityTrustHtml(html); }`));
    expect(res).toHaveLength(1);
    expect(res[0]!.confidence).toBe('low');
    expect(res[0]!.evidenceKind).toBe('heuristic');
  });

  it('false-positive regression: same-named method on an unrelated project class is ignored', async () => {
    expect(await one('NGB001', `export class Fake { bypassSecurityTrustHtml(v: string) { return v; } }
export class Y { f = new Fake(); go() { return this.f.bypassSecurityTrustHtml(location.hash); } }`)).toEqual([]);
  });
});
