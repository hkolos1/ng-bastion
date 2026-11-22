// Fixture for CLI integration tests. Intentionally vulnerable.
export function renderBanner(el: HTMLElement): void {
  const message = decodeURIComponent(location.hash.slice(1));
  el.innerHTML = `<p>${message}</p>`;
}

export function calculate(): unknown {
  return eval(new URLSearchParams(location.search).get('expr') ?? '0');
}

export function safe(el: HTMLElement): void {
  el.textContent = location.hash;
}
