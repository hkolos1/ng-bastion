import { describe, expect, it } from 'vitest';
import { NG, one } from './helpers.js';

const widget = (handlerBody: string) => `${NG}import { HostListener, ViewChild } from '@angular/core';
export class Embed {
  @ViewChild('frame') frame!: ElementRef<HTMLIFrameElement>;
  height = 0;
  ping() { this.frame.nativeElement.contentWindow?.postMessage('hello', 'https://widget.example.com'); }
  @HostListener('window:message', ['$event'])
  onMessage(e: MessageEvent) { ${handlerBody} }
}`;

describe('NGB008 unverified message source', () => {
  it('reports a frame-specific handler that never checks event.source (medium)', async () => {
    const [f, ...rest] = await one('NGB008', widget(`if (e.origin !== 'https://widget.example.com') return; this.height = e.data.height;`));
    expect(rest).toHaveLength(0);
    expect(f!.severity).toBe('medium');
    expect(f!.confidence).toBe('medium');
    expect(f!.evidence[0]).toMatch(/contentWindow/);
  });

  it('accepts a source check (safe equivalent)', async () => {
    expect(await one('NGB008', widget(`if (e.source !== this.frame.nativeElement.contentWindow) return; this.height = e.data.height;`))).toEqual([]);
  });

  it('is silent when no specific peer window is involved', async () => {
    expect(await one('NGB008', `export function a(el: HTMLElement) { window.addEventListener('message', (e) => { if (e.origin === 'https://a.com') el.textContent = e.data; }); }`)).toEqual([]);
  });

  it('covers popups opened with window.open()', async () => {
    const res = await one('NGB008', `export class Login {
  popup: Window | null = null;
  start() { this.popup = window.open('https://idp.example.com/login'); window.addEventListener('message', (e) => this.done(e)); }
  done(e: MessageEvent) { if (e.origin === 'https://idp.example.com') sessionStorage.setItem('state', e.data.state); }
}`);
    expect(res).toHaveLength(1);
    expect(res[0]!.evidence[0]).toMatch(/window.open/);
  });

  it('false-positive regression: a source reference that guards processing is enough', async () => {
    expect(await one('NGB008', `export class L {
  popup = window.open('https://idp.example.com');
  init() { window.addEventListener('message', (e) => { if (e.source === this.popup && e.origin === 'https://idp.example.com') console.log(e.data); }); }
}`)).toEqual([]);
  });
});
