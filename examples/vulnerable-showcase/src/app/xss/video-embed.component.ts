import { Component, inject } from '@angular/core';
import { DomSanitizer, SafeResourceUrl } from '@angular/platform-browser';
import { ActivatedRoute } from '@angular/router';

@Component({
  selector: 'app-video-embed',
  template: `<iframe [src]="videoUrl" title="Video" sandbox="allow-scripts"></iframe>`,
})
export class VideoEmbedComponent {
  private readonly sanitizer = inject(DomSanitizer);
  private readonly route = inject(ActivatedRoute);

  // NGB002: any URL from the query string is trusted as an iframe resource.
  readonly videoUrl: SafeResourceUrl = this.sanitizer.bypassSecurityTrustResourceUrl(this.route.snapshot.queryParams['video']);
}
