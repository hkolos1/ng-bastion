import { ChangeDetectionStrategy, Component } from '@angular/core';
import { RouterLink } from '@angular/router';
import { SHOWCASE } from '../home/showcase';

@Component({
  selector: 'ngb-site-footer',
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [RouterLink],
  template: `
    <footer class="site-footer">
      <div class="shell footer-main">
        <div class="footer-brand">
          <a class="brand" routerLink="/" aria-label="NgBastion home">
            <img class="only-dark" src="/brand/logo-mark-dark.svg" alt="" width="24" height="24" />
            <img class="only-light" src="/brand/logo-mark-light.svg" alt="" width="24" height="24" />
            <span>NgBastion</span>
          </a>
          <p>Angular-aware, local-first security analysis. Follows untrusted data from source to sink and shows its evidence.</p>
        </div>
        @for (group of groups; track group.label) {
          <nav class="footer-group" [attr.aria-label]="group.label">
            <p class="label">{{ group.label }}</p>
            <ul>
              @for (l of group.links; track l[0]) {
                <li><a [routerLink]="l[0]">{{ l[1] }}</a></li>
              }
            </ul>
          </nav>
        }
      </div>
      <div class="footer-meta">
        <div class="shell footer-meta-inner">
          <span>MIT license</span>
          <span>v{{ version }} · private development</span>
          <span>Repository private until the first public release</span>
          <span>Angular {{ angularMajor }} + AnalogJS · no analytics</span>
        </div>
      </div>
    </footer>
  `,
})
export class SiteFooter {
  protected readonly angularMajor = 22;
  protected readonly version = SHOWCASE.version;
  protected readonly groups = [
    { label: 'Product', links: [['/docs', 'Documentation'], ['/rules', 'Security rules'], ['/playground', 'Playground'], ['/changelog', 'Changelog']] },
    { label: 'Reference', links: [['/docs/cli-reference', 'CLI reference'], ['/docs/configuration', 'Configuration'], ['/docs/limitations', 'Limitations'], ['/docs/security-policy', 'Security policy']] },
  ];
}
