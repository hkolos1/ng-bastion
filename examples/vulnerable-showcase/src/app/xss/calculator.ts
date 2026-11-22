/** NGB004: evaluates an expression taken from the URL fragment. */
export function evaluateFromHash(): unknown {
  const expression = decodeURIComponent(window.location.hash.slice(1));
  return eval(expression);
}

/** NGB005: loads a "widget" script chosen by the query string. */
export function loadWidget(): void {
  const script = document.createElement('script');
  script.src = new URLSearchParams(window.location.search).get('widget') ?? '';
  document.head.appendChild(script);
}

/** NGB003: renders a fragment-provided banner as raw HTML. */
export function showBanner(target: HTMLElement): void {
  target.innerHTML = `<div class="banner">${decodeURIComponent(location.hash.slice(1))}</div>`;
}
