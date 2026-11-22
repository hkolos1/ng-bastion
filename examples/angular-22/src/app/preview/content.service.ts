import { Injectable, inject } from '@angular/core';
import { ActivatedRoute } from '@angular/router';

@Injectable({ providedIn: 'root' })
export class ContentService {
  private readonly route = inject(ActivatedRoute);

  previewHtml(): string {
    const raw = this.route.snapshot.queryParamMap.get('preview') ?? '';
    return `<article>${raw}</article>`;
  }
}
