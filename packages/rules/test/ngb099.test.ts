import { describe, expect, it } from 'vitest';
import { findings, one } from './helpers.js';

const NF = `import { loadRemoteModule, initFederation } from '@angular-architects/native-federation';
import { ActivatedRoute } from '@angular/router';
`;

describe('NGB099 untrusted module federation remote', () => {
  it('reports remote entries traced to the URL', async () => {
    const res = await one('NGB099', `${NF}export class C {
  constructor(private route: ActivatedRoute) {}
  load() { return loadRemoteModule({ remoteEntry: this.route.snapshot.queryParams['remote'], exposedModule: './Routes' }); }
  init() { return initFederation({ mfe: localStorage.getItem('mfe-url')! }); }
}`);
    expect(res).toHaveLength(2);
    expect(res.every((f) => f.evidenceKind === 'dataflow')).toBe(true);
  });

  it('reports plain-HTTP remotes in code, @module-federation runtime and manifests', async () => {
    const res = await findings('NGB099', {
      'src/main.ts': `import { init } from '@module-federation/enhanced/runtime';
import { initFederation } from '@angular-architects/native-federation';
init({ name: 'host', remotes: [{ name: 'shop', entry: 'http://shop.example.com/mf-manifest.json' }] });
initFederation('http://cdn.example.com/federation.manifest.json');`,
      'public/federation.manifest.json': JSON.stringify({ shop: 'http://shop.example.com/remoteEntry.json', cart: 'https://cart.example.com/remoteEntry.json' }),
    });
    expect(res).toHaveLength(3);
  });

  it('safe: constant https remotes, remote names, local development hosts', async () => {
    expect(await one('NGB099', `${NF}
initFederation({ mfe: 'https://mfe.example.com/remoteEntry.json', dev: 'http://localhost:4201/remoteEntry.json' });
loadRemoteModule('mfe', './Routes');`)).toEqual([]);
  });

  it('false-positive regression: same-named functions from other modules', async () => {
    expect(await one('NGB099', `import { ActivatedRoute } from '@angular/router';
function loadRemoteModule(o: { remoteEntry: string }) { return o; }
export class C { constructor(private route: ActivatedRoute) {}
  go() { return loadRemoteModule({ remoteEntry: this.route.snapshot.queryParams['x'] }); } }`)).toEqual([]);
  });
});
