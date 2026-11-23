import { Component, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { ActivatedRoute } from '@angular/router';

@Component({
  selector: 'app-project-actions',
  // NGB027: the API key ends up in the DOM (and in SSR HTML).
  template: `<button (click)="archive()" [attr.data-api-key]="apiKey">Archive</button>`,
})
export class ProjectActionsComponent {
  private readonly http = inject(HttpClient);
  private readonly route = inject(ActivatedRoute);
  apiKey = '';

  archive(): void {
    const id = this.route.snapshot.paramMap.get('id');
    // NGB026: id = "..%2F..%2Fadmin%2Fusers%2F1" turns this into DELETE /api/admin/users/1 (client-side path traversal).
    this.http.delete(`/api/projects/${id}`, { withCredentials: true }).subscribe();
    // Safe counterpart: validated and encoded identifier (not reported).
    if (id && /^[0-9]+$/.test(id)) this.http.post(`/api/projects/${encodeURIComponent(id)}/star`, {}).subscribe();
  }
}
