import type { RouteMeta } from '@analogjs/router';
import { pageResolver } from '../../core/page.resolver';
import { RulesIndexPage } from '../../rules/rules-index-page';

export const routeMeta: RouteMeta = { resolve: { page: pageResolver } };

export default RulesIndexPage;
