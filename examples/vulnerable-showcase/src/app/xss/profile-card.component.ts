import { Component, inject } from '@angular/core';
import { DomSanitizer, SafeHtml } from '@angular/platform-browser';
import { BioService } from './bio.service';

@Component({
  selector: 'app-profile-card',
  template: `<section [innerHTML]="bio"></section>`,
})
export class ProfileCardComponent {
  private readonly sanitizer = inject(DomSanitizer);
  private readonly bios = inject(BioService);

  // NGB001: URL data marked as trusted HTML — Angular will not sanitize it.
  readonly bio: SafeHtml = this.sanitizer.bypassSecurityTrustHtml(this.bios.previewBio());
}
