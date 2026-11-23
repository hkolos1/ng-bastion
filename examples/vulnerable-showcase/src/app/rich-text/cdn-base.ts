import { APP_BASE_HREF } from '@angular/common';

/** NGB054: the "cdn" query parameter decides where every relative URL resolves. */
export function applyCdnBase(): void {
  const base = document.querySelector('base');
  if (base) base.href = new URLSearchParams(location.search).get('cdn') ?? '/';
}

export const baseHrefProvider = { provide: APP_BASE_HREF, useFactory: () => new URLSearchParams(location.search).get('base') ?? '/' };
