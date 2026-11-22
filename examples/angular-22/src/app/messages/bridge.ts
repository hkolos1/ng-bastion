/** NGB007/NGB009/NGB011: unvalidated cross-window message drives navigation. */
export function listenForRedirects(): void {
  window.addEventListener('message', (event: MessageEvent) => {
    window.location.href = event.data.redirectUrl;
  });
}

/** Safe equivalent: strict origin allowlist and same-origin redirect check. */
const TRUSTED_ORIGINS = ['https://accounts.example.com'];
export function listenSafely(): void {
  window.addEventListener('message', (event: MessageEvent) => {
    if (!TRUSTED_ORIGINS.includes(event.origin)) return;
    if (typeof event.data?.path !== 'string') return;
    const target = new URL(event.data.path, window.location.origin);
    if (target.origin !== window.location.origin) return;
    window.location.assign(target.pathname);
  });
}
