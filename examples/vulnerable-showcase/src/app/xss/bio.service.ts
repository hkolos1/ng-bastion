import { Injectable, inject } from '@angular/core';
import { ActivatedRoute } from '@angular/router';

@Injectable({ providedIn: 'root' })
export class BioService {
  private readonly route = inject(ActivatedRoute);

  /** Reads a "preview" bio straight from the URL. */
  previewBio(): string {
    const bio = this.route.snapshot.queryParamMap.get('bio') ?? '';
    return `<p class="bio">${bio}</p>`;
  }
}
