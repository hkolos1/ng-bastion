import { ChangeDetectionStrategy, Component } from '@angular/core';
import { RouterLink } from '@angular/router';

@Component({
  selector: 'ngb-site-footer',
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [RouterLink],
  template: `
    <footer class="site-footer">
      <div class="shell site-footer-inner">
        <div>
          <p class="label">NgBastion</p>
          <p>MIT-licensed, open-source Angular security analysis in private development. Scans run locally. This site uses no analytics and loads no third-party resources.</p>
          <p>Built with Angular {{ angularMajor }} and AnalogJS, pre-rendered for every route.</p>
        </div>
        <nav aria-label="Documentation links">
          <p class="label">Documentation</p>
          <ul>
            <li><a routerLink="/docs/getting-started/installation">Getting started</a></li>
            <li><a routerLink="/docs/cli-reference">CLI reference</a></li>
            <li><a routerLink="/rules">Security rules</a></li>
            <li><a routerLink="/docs/configuration">Configuration</a></li>
          </ul>
        </nav>
        <nav aria-label="Project links">
          <p class="label">Project</p>
          <ul>
            <li><a routerLink="/playground">Playground</a></li>
            <li><a routerLink="/changelog">Changelog</a></li>
            <li><a routerLink="/docs/limitations">Limitations</a></li>
            <li><a routerLink="/docs/security-policy">Security policy</a></li>
          </ul>
        </nav>
      </div>
    </footer>
  `,
})
export class SiteFooter {
  protected readonly angularMajor = 22;
}
