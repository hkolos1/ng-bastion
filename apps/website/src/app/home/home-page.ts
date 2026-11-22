import { ChangeDetectionStrategy, Component, inject } from '@angular/core';
import { RouterLink } from '@angular/router';
import { Seo } from '../core/seo.service';
import { LANDING, SHOWCASE } from './showcase';
import { TerminalDemo } from './terminal-demo';
import { DataFlow } from './data-flow';
import { CodeBlock } from '../ui/code-block';

const DESCRIPTION = 'NgBastion is an Angular-aware, local-first security scanner. It traces untrusted data from URLs, messages and API responses to dangerous sinks and explains every finding.';

@Component({
  selector: 'ngb-home-page',
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [RouterLink, TerminalDemo, DataFlow, CodeBlock],
  template: `
    <div class="hero-wrap">
      <div class="shell">
        <section class="hero" aria-labelledby="hero-h">
          <div class="hero-copy">
            <h1 id="hero-h" class="hero-title"><span class="line">Your <span class="hl">Angular</span></span>&ngsp;<span class="line">security stronghold.</span></h1>
            <p class="lead">NgBastion follows untrusted data from URLs, window messages and API responses through your services, RxJS pipelines and signals, and shows the exact path to every dangerous sink. Locally, with the evidence attached.</p>
            <div class="hero-actions">
              <a class="btn btn-primary" routerLink="/docs/getting-started/installation">Get started<svg viewBox="0 0 16 16" aria-hidden="true"><path d="M3 8h9M8.5 4.5 12 8l-3.5 3.5" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/></svg></a>
              <a class="btn" routerLink="/rules">Browse {{ showcase.ruleCount }} rules</a>
              <a class="btn btn-ghost" routerLink="/playground">Playground<svg viewBox="0 0 16 16" aria-hidden="true"><path d="M3 8h9M8.5 4.5 12 8l-3.5 3.5" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/></svg></a>
            </div>
            <dl class="hero-stats">
              <div><dt>{{ showcase.ruleCount }}</dt><dd>security rules</dd></div>
              <div><dt>20–22</dt><dd>Angular versions tested</dd></div>
              <div><dt>0</dt><dd>network requests per scan</dd></div>
            </dl>
          </div>
          <ngb-terminal-demo [data]="showcase" />
        </section>
      </div>
    </div>

    <div class="shell">
      <section class="section engine" aria-labelledby="engine-h">
        <div class="engine-grid">
          <div class="section-head sticky-head">
            <p class="label">Type-aware data-flow engine</p>
            <h2 id="engine-h">Follows the data, not just the function name.</h2>
            <p class="lead">A real finding from the showcase app, step by step. Every line below is the actual source NgBastion traced, across files, from an untrusted query parameter to a trust bypass.</p>
            <ul class="engine-points">
              @for (p of enginePoints; track p[0]) {
                <li><strong>{{ p[0] }}</strong><span>{{ p[1] }}</span></li>
              }
            </ul>
            <a class="text-link" routerLink="/docs/security-engine">How the engine works →</a>
          </div>
          <ngb-data-flow [data]="showcase" />
        </div>
      </section>

      <section class="section" aria-labelledby="aware-h">
        <div class="section-head">
          <p class="label">Angular-aware</p>
          <h2 id="aware-h">Knows what Angular already protects.</h2>
          <p class="lead">Both snippets render a query parameter as HTML. NgBastion scanned them when this site was built, and only one is a problem.</p>
        </div>
        <div class="compare">
          @for (c of landing.comparison; track c.id) {
            <div class="compare-item" [class.flagged]="c.findings.length">
              <div class="compare-head">
                <h3>{{ c.title }}</h3>
                @if (c.findings.length) {
                  <span class="verdict verdict-bad"><span class="sev-badge" [class]="'sev-badge sev-' + c.findings[0]!.severity">{{ c.findings[0]!.ruleId }}</span>reported</span>
                } @else {
                  <span class="verdict verdict-ok"><svg viewBox="0 0 16 16" aria-hidden="true"><path d="M3.5 8.5 6.5 11.5 12.5 4.5" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg>no findings</span>
                }
              </div>
              <p class="compare-caption">{{ c.caption }}</p>
              <ngb-code-block [snippet]="c" filename="preview.component.ts" />
            </div>
          }
        </div>
      </section>

      <section class="section" aria-labelledby="cap-h">
        <div class="section-head">
          <p class="label">Capabilities</p>
          <h2 id="cap-h">Built for security reviews you can trust.</h2>
        </div>
        <div class="features">
          @for (c of capabilities; track c.title) {
            <div class="feature">
              <span class="feature-icon" aria-hidden="true"><svg viewBox="0 0 24 24"><path [attr.d]="c.icon" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/></svg></span>
              <h3>{{ c.title }}</h3>
              <p>{{ c.text }}</p>
            </div>
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
            <div class="panel-title"><span class="status status-ok">Available now</span><h3>From a checkout</h3></div>
            <ngb-code-block [snippet]="landing.commands.local" filename="terminal" />
          </div>
          <div class="panel-card planned">
            <div class="panel-title"><span class="status">Planned</span><h3>Once published to npm</h3></div>
            <ngb-code-block [snippet]="landing.commands.planned" filename="terminal" />
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

      <section class="section closing" aria-labelledby="limits-h">
        <div class="section-head">
          <p class="label">Honest by design</p>
          <h2 id="limits-h">What a clean report means.</h2>
          <p class="lead">NgBastion reports the patterns and data flows it models, with the confidence its evidence supports. It does not replace penetration testing, server-side authorization or browser security controls, and no findings never proves an application is secure. The <a routerLink="/docs/limitations">limitations</a> are documented as carefully as the rules.</p>
        </div>
        <div class="hero-actions">
          <a class="btn btn-primary" routerLink="/docs/getting-started/first-scan">Run your first scan</a>
          <a class="btn" routerLink="/docs/limitations">Read the limitations</a>
        </div>
      </section>
    </div>
  `,
})
export class HomePage {
  protected readonly showcase = SHOWCASE;
  protected readonly landing = LANDING;
  protected readonly enginePoints: [string, string][] = [
    ['Symbols, not names', 'APIs are identified through the TypeScript TypeChecker, with import-based fallback when dependencies are not installed.'],
    ['Across your codebase', 'Arguments, returns, class fields and injected services across files, plus selected RxJS operators and signals.'],
    ['Context-aware sanitizers', 'An HTML sanitizer does not make a URL safe; bypassSecurityTrust* never counts as sanitization.'],
    ['Bounded and explicit', 'Depth, call-site and time limits; when one is hit you get a diagnostic, not silence.'],
  ];
  protected readonly capabilities = [
    { title: 'Understands Angular', text: 'Sanitized [innerHTML] bindings, DomSanitizer, ElementRef, Renderer2, ActivatedRoute, HttpClient, interceptors, TransferState, signals and inject().', icon: 'M12 3l8 3-1.2 10.2L12 21l-6.8-4.8L4 6l8-3Zm0 0v18M8.5 15l3.5-8 3.5 8M9.6 12.5h4.8' },
    { title: 'Explains every finding', text: 'Data-flow findings carry the observed path. Confidence is separate from severity; analysis gaps become diagnostics.', icon: 'M5 6h14M5 12h9M5 18h6M17 15l2 2 3-4' },
    { title: `${SHOWCASE.ruleCount} security rules`, text: 'Trust bypasses, DOM sinks, cross-window messaging, redirects, credential forwarding, token and payment storage, secrets, CSP, SSR state.', icon: 'M12 3l7 3v5c0 4.4-3 8.2-7 10-4-1.8-7-5.6-7-10V6l7-3Zm-3 9 2 2 4-4' },
    { title: 'Local-first', text: 'Runs on your machine or CI runner. No uploads, no account, no telemetry.', icon: 'M4 6h16v10H4zM2 20h20M9 16v4M15 16v4' },
    { title: 'Policies and exceptions', text: 'JSON or TypeScript config, presets, shared configs, mandatory rules and expiring, justified exceptions.', icon: 'M6 4h9l3 3v13H6zM9 11h6M9 15h6M14 4v4h4' },
    { title: 'Built for pipelines', text: 'Predictable exit codes, SARIF 2.1.0 for GitHub code scanning, JSON reports and templates for four CI systems.', icon: 'M5 7h4v4H5zM15 13h4v4h-4zM9 9h3a2 2 0 0 1 2 2v2a2 2 0 0 0 2 2' },
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
