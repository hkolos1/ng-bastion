import type { RouteMeta } from '@analogjs/router';
import { pageResolver } from '../core/page.resolver';
import { DocPage } from '../content/doc-page';

export const routeMeta: RouteMeta = { resolve: { page: pageResolver } };

export default DocPage;
