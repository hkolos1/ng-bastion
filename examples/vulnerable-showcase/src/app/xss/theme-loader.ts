import { Injectable, inject } from '@angular/core';
import { ActivatedRoute } from '@angular/router';

@Injectable({ providedIn: 'root' })
export class ThemeLoader {
  private readonly route = inject(ActivatedRoute);

  /** NGB064: the `theme` query parameter becomes a style sheet. */
  applyTheme(): void {
    const style = document.createElement('style');
    style.textContent = this.route.snapshot.queryParams['theme'];
    document.head.appendChild(style);
  }

  /** NGB063: an element with id="WIDGET_CONFIG" in injected HTML controls the script URL. */
  loadWidget(): void {
    const cfg = (window as any).WIDGET_CONFIG || {};
    const script = document.createElement('script');
    script.src = cfg.cdn + '/widget.js';
    document.body.appendChild(script);
  }
}
