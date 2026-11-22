import { inject } from '@angular/core';
import { RedirectCommand, Router, type ResolveFn } from '@angular/router';
import { loadPage, slugFromUrl, type PageData } from './content';

/** Resolves the generated page for the current URL; unknown slugs go to the not-found page. */
export const pageResolver: ResolveFn<PageData> = async (_route, state) => {
  const page = await loadPage(slugFromUrl(state.url));
  if (page) return page;
  const router = inject(Router);
  return new RedirectCommand(router.parseUrl('/404'), { skipLocationChange: true });
};
