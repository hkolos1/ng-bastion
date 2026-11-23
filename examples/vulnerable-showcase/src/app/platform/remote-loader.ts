import { inject } from '@angular/core';
import { ActivatedRoute } from '@angular/router';
import { loadRemoteModule } from '@angular-architects/native-federation';

/** Micro-frontend loader with a "testing" override. */
export function loadFeature() {
  const route = inject(ActivatedRoute);
  // NGB099: any link can make the app load and run a remote from the attacker's server.
  const remoteEntry = route.snapshot.queryParams['remote'] ?? 'https://mfe.example.com/remoteEntry.json';
  return loadRemoteModule({ remoteEntry, exposedModule: './Routes' });
}

/** Installs a module override for support sessions. */
export function installOverrides(): void {
  const overrides = new URLSearchParams(location.search).get('modules') ?? '{}';
  const script = document.createElement('script');
  script.type = 'importmap';
  // NGB100: the import map comes from the URL — any module can be remapped to the attacker's code.
  script.textContent = `{"imports": ${overrides}}`;
  document.head.append(script);
}
