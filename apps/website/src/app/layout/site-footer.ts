import { ChangeDetectionStrategy, Component } from '@angular/core';
import { RouterLink } from '@angular/router';

@Component({
  selector: 'ngb-site-footer',
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [RouterLink],
  template: `
    <footer class="site-footer">
      <p>NgBastion is MIT-licensed, open-source software in private development. The GitHub repository is private until the first public release.</p>
      <p>Scans run locally. This site uses no analytics and loads no third-party resources. Built with Angular {{ angularMajor }} and AnalogJS, pre-rendered for every route.</p>
      <p><a routerLink="/docs/security-policy">Security policy</a> · <a routerLink="/docs/limitations">Limitations</a> · <a routerLink="/changelog">Changelog</a></p>
    </footer>
  `,
})
export class SiteFooter {
  protected readonly angularMajor = 22;
}
