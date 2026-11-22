import { ChangeDetectionStrategy, Component, inject } from '@angular/core';
import { RouterLink } from '@angular/router';
import { Seo } from '../core/seo.service';
import { SHOWCASE } from './showcase';
import { TerminalDemo } from './terminal-demo';

const DESCRIPTION = 'NgBastion is an Angular-aware, local-first security scanner. It traces untrusted data from URLs, messages and API responses to dangerous sinks and explains every finding.';

@Component({
  selector: 'ngb-home-page',
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [RouterLink, TerminalDemo],
  template: `
    <section class="hero">
      <div class="hero-copy">
        <h1>NgBastion</h1>
        <p class="tagline">Your Angular security stronghold.</p>
        <p class="lede">An Angular-aware, local-first security scanner. It follows untrusted data from URLs, window messages and API responses through your services, RxJS pipes and signals, and shows you the exact path it took to a dangerous sink.</p>
        <div class="actions">
          <a class="btn btn-primary" routerLink="/docs/getting-started/installation">Get started</a>
          <a class="btn" routerLink="/rules">Browse the rules</a>
        </div>
        <p class="hero-note">Version {{ showcase.version }} is in private development. The npm package is not published yet.</p>
      </div>
      <ngb-terminal-demo [data]="showcase" />
    </section>

    <section aria-labelledby="cap-h">
      <h2 id="cap-h">Security checks that understand Angular</h2>
      <p class="lede">Generic linters see <code>innerHTML</code>. NgBastion asks where the value came from, whether Angular already sanitized it, and how sure it can be.</p>
      <dl class="caps">
        @for (c of capabilities; track c[0]) {
          <div><dt>{{ c[0] }}</dt><dd>{{ c[1] }}</dd></div>
        }
      </dl>
    </section>

    <section aria-labelledby="start-h" class="start">
      <h2 id="start-h">Getting started</h2>
      <div class="start-grid">
        <div>
          <h3>Available now: from a checkout</h3>
          <pre><code><span class="prompt">$</span> pnpm install &amp;&amp; pnpm build
<span class="prompt">$</span> node packages/cli/dist/bin.js scan ../my-angular-app
<span class="prompt">$</span> node packages/cli/dist/bin.js scan ../my-angular-app \\
    --format sarif --output results.sarif</code></pre>
        </div>
        <div>
          <h3>Planned: once published to npm</h3>
          <pre class="planned"><code><span class="prompt">$</span> npx ngbastion scan
<span class="prompt">$</span> npx ngbastion init --preset recommended
<span class="prompt">$</span> npx ngbastion explain NGB001</code></pre>
          <p class="t-small">These commands describe the intended interface. They will not work until the first public release.</p>
        </div>
      </div>
    </section>

    <section aria-labelledby="docs-h">
      <h2 id="docs-h">Documentation</h2>
      <ul class="doc-links">
        @for (d of docs; track d[0]) {
          <li><a [routerLink]="d[0]"><span class="doc-t">{{ d[1] }}</span><span class="doc-d">{{ d[2] }}</span></a></li>
        }
      </ul>
    </section>

    <section aria-labelledby="limits-h" class="honest">
      <h2 id="limits-h">What a clean report means</h2>
      <p>NgBastion reports the patterns and data flows it models, with the confidence its evidence supports. It does not replace penetration testing, server-side authorization or browser security controls, and no findings never proves an application is secure. The <a routerLink="/docs/limitations">limitations</a> are documented as carefully as the rules.</p>
    </section>
  `,
})
export class HomePage {
  protected readonly showcase = SHOWCASE;
  protected readonly capabilities: [string, string][] = [
    ['Understands Angular', 'Knows that [innerHTML] bindings are sanitized, and recognizes DomSanitizer, ElementRef, Renderer2, ActivatedRoute, HttpClient, interceptors, TransferState, signals and inject().'],
    ['Type-aware data flow', 'Built on the TypeScript Compiler API. Follows values across files, services, function calls, selected RxJS operators and signals, matching APIs by symbol rather than by name.'],
    ['Explains every finding', 'Data-flow findings carry the observed path from source to sink. Confidence is reported separately from severity, and analysis gaps appear as diagnostics.'],
    [`${SHOWCASE.ruleCount} security rules`, 'XSS and trust bypasses, cross-window messaging, redirects and credential forwarding, token and payment storage, secrets, CSP and Trusted Types, SSR state.'],
    ['Local-first', 'Runs on your machine or CI runner. No uploads, no account, no telemetry.'],
    ['Policy for teams', 'JSON or TypeScript config, presets, shared configurations, mandatory rules, expiring exceptions with justifications.'],
    ['Made for CI', 'Exit codes for security gates and templates for GitHub Actions, GitLab CI, Jenkins and Azure DevOps.'],
    ['SARIF and JSON reports', 'SARIF 2.1.0 with code flows for GitHub code scanning, and a versioned JSON schema for your own tooling.'],
  ];
  protected readonly docs: [string, string, string][] = [
    ['/docs/getting-started/installation', 'Getting started', 'Local setup and your first scan'],
    ['/docs/cli-reference', 'CLI reference', 'scan, init, explain, rules and doctor'],
    ['/rules', 'Security rules', 'What each of the rules detects, and what it does not'],
    ['/docs/configuration', 'Configuration', 'Presets, policies and exceptions'],
    ['/docs/plugin-api', 'Plugin API', 'Write trusted custom rules'],
    ['/docs/ci-cd', 'CI/CD', 'Gates, artifacts and SARIF upload'],
  ];

  constructor() {
    inject(Seo).set({
      title: 'NgBastion: Angular-aware security scanner',
      description: DESCRIPTION,
      path: '/',
      jsonLd: {
        '@context': 'https://schema.org',
        '@type': 'SoftwareApplication',
        name: 'NgBastion',
        applicationCategory: 'DeveloperApplication',
        operatingSystem: 'Linux, macOS, Windows (Node.js 22 or 24)',
        softwareVersion: SHOWCASE.version,
        description: DESCRIPTION,
        url: 'https://ngbastion.dev/',
        license: 'https://opensource.org/licenses/MIT',
      },
    });
  }
}
