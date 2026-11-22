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
    <div class="shell">
      <section class="hero" aria-labelledby="hero-h">
        <div class="hero-copy">
          <p class="label">NgBastion · Angular security scanner</p>
          <h1 id="hero-h">Your Angular security stronghold.</h1>
          <p class="lead">A local-first scanner that understands Angular. It follows untrusted data from URLs, window messages and API responses through services, RxJS and signals, and shows the exact path to every dangerous sink.</p>
          <div class="hero-actions">
            <a class="btn btn-primary" routerLink="/docs/getting-started/installation">Get started</a>
            <a class="btn" routerLink="/rules">Browse {{ showcase.ruleCount }} rules</a>
          </div>
          <p class="hero-note">v{{ showcase.version }} · private development · not yet published to npm</p>
        </div>
        <ngb-terminal-demo [data]="showcase" />
      </section>

      <section class="section" aria-labelledby="flow-h">
        <div class="section-head">
          <p class="label">Source → sink tracing</p>
          <h2 id="flow-h">Follows the data, not just the function name.</h2>
          <p class="lead">Generic linters see <code>innerHTML</code>. NgBastion asks where the value came from, whether Angular already sanitized it, and how sure it can be.</p>
        </div>
        <div class="flow-explainer">
          <div class="flow-step source"><p class="label"><span class="dot"></span>Source</p><p>Query parameters, fragments, <code>MessageEvent.data</code>, form input, storage and HTTP responses, each with its own trust level.</p></div>
          <div class="flow-step"><p class="label"><span class="dot"></span>Propagation</p><p>Assignments, calls and returns across files, injected services, selected RxJS operators and signals. Sanitizers are honoured per context.</p></div>
          <div class="flow-step sink"><p class="label"><span class="dot"></span>Sink</p><p>Trust bypasses, raw DOM writes, <code>eval</code>, redirects, storage, logging and SSR state. Every step is reported with file and line.</p></div>
        </div>
      </section>

      <section class="section" aria-labelledby="cap-h">
        <div class="section-head">
          <p class="label">Capabilities</p>
          <h2 id="cap-h">Security checks that understand Angular.</h2>
        </div>
        <div class="features">
          @for (c of capabilities; track c[1]) {
            <div class="feature"><p class="label">{{ c[0] }}</p><h3>{{ c[1] }}</h3><p>{{ c[2] }}</p></div>
          }
        </div>
      </section>

      <section class="section" aria-labelledby="start-h">
        <div class="section-head">
          <p class="label">Getting started</p>
          <h2 id="start-h">Run it on your workspace.</h2>
        </div>
        <div class="panels">
          <div class="panel-card">
            <h3>Available now: from a checkout</h3>
            <pre class="cmd"><code><span class="prompt">$ </span>pnpm install &amp;&amp; pnpm build
<span class="prompt">$ </span>node packages/cli/dist/bin.js scan ../my-angular-app
<span class="prompt">$ </span>node packages/cli/dist/bin.js scan ../my-angular-app \\
    --format sarif --output results.sarif</code></pre>
          </div>
          <div class="panel-card planned">
            <h3>Planned: once published to npm</h3>
            <pre class="cmd"><code><span class="prompt">$ </span>npx ngbastion scan
<span class="prompt">$ </span>npx ngbastion init --preset recommended
<span class="prompt">$ </span>npx ngbastion explain NGB001</code></pre>
            <p>These commands describe the intended interface. They will not work until the first public release.</p>
          </div>
        </div>
      </section>

      <section class="section" aria-labelledby="docs-h">
        <div class="section-head">
          <p class="label">Documentation</p>
          <h2 id="docs-h">Everything is documented, including the gaps.</h2>
        </div>
        <ul class="link-grid">
          @for (d of docs; track d[0]) {
            <li><a class="link-card" [routerLink]="d[0]"><strong>{{ d[1] }}</strong><span>{{ d[2] }}</span></a></li>
          }
        </ul>
      </section>

      <section class="section" aria-labelledby="limits-h">
        <div class="section-head">
          <p class="label">Honest by design</p>
          <h2 id="limits-h">What a clean report means.</h2>
          <p class="lead">NgBastion reports the patterns and data flows it models, with the confidence its evidence supports. It does not replace penetration testing, server-side authorization or browser security controls, and no findings never proves an application is secure. The <a routerLink="/docs/limitations">limitations</a> are documented as carefully as the rules.</p>
        </div>
      </section>
    </div>
  `,
})
export class HomePage {
  protected readonly showcase = SHOWCASE;
  protected readonly capabilities: [string, string, string][] = [
    ['Angular', 'Understands Angular', 'Knows [innerHTML] bindings are sanitized; recognizes DomSanitizer, ElementRef, Renderer2, ActivatedRoute, HttpClient, interceptors, TransferState, signals and inject().'],
    ['Data flow', 'Type-aware tracing', 'Built on the TypeScript Compiler API. Matches APIs by symbol, not by name, across files, services, RxJS and signals.'],
    ['Evidence', 'Explains every finding', 'Data-flow findings carry the observed path. Confidence is separate from severity; analysis gaps become diagnostics.'],
    ['Coverage', `${SHOWCASE.ruleCount} security rules`, 'Trust bypasses, DOM sinks, cross-window messaging, redirects, credential forwarding, token and payment storage, secrets, CSP, SSR state.'],
    ['Privacy', 'Local-first', 'Runs on your machine or CI runner. No uploads, no account, no telemetry.'],
    ['Teams', 'Policies and exceptions', 'JSON or TypeScript config, presets, shared configs, mandatory rules and expiring, justified exceptions.'],
    ['CI', 'Built for pipelines', 'Predictable exit codes and templates for GitHub Actions, GitLab CI, Jenkins and Azure DevOps.'],
    ['Reports', 'SARIF and JSON', 'SARIF 2.1.0 with code flows for GitHub code scanning, plus a versioned JSON schema.'],
  ];
  protected readonly docs: [string, string, string][] = [
    ['/docs/getting-started/installation', 'Getting started', 'Local setup and your first scan'],
    ['/docs/cli-reference', 'CLI reference', 'scan, init, explain, rules and doctor'],
    ['/rules', 'Security rules', 'What each rule detects, and what it does not'],
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
