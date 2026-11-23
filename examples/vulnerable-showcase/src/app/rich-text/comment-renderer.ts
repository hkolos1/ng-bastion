import { Component, Injectable, Sanitizer, SecurityContext, inject } from '@angular/core';
import { DomSanitizer, type SafeHtml } from '@angular/platform-browser';
import { ActivatedRoute } from '@angular/router';

declare const trustedTypes: { createPolicy(name: string, rules: object): unknown };

/** NGB052: replaces Angular's sanitizer application-wide with a no-op. */
@Injectable()
export class PermissiveSanitizer extends Sanitizer {
  sanitize(_context: SecurityContext, value: string | null): string | null {
    return value;
  }
}
export const sanitizerProviders = [{ provide: Sanitizer, useClass: PermissiveSanitizer }];

// NGB056: a pass-through default policy approves every string for every DOM sink.
trustedTypes.createPolicy('default', { createHTML: (html: string) => html });

@Component({ selector: 'app-comment', template: '<div [innerHTML]="html"></div>' })
export class CommentRendererComponent {
  private readonly sanitizer = inject(DomSanitizer);
  private readonly route = inject(ActivatedRoute);
  html: SafeHtml = '';

  render(comment: string): void {
    // NGB051: URL sanitization does not make HTML safe, yet the result is trusted as HTML.
    const cleaned = this.sanitizer.sanitize(SecurityContext.URL, comment) ?? '';
    this.html = this.sanitizer.bypassSecurityTrustHtml(cleaned);
  }

  /** NGB053: the layout parameter becomes a runtime-compiled component template. */
  customLayout(): unknown {
    const layout = this.route.snapshot.queryParamMap.get('layout') ?? '';
    return Component({ selector: 'app-custom-layout', template: layout })(class {});
  }
}
