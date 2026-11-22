import type { SecurityRule } from '@ngbastion/plugin-api';
import { ngb016 } from './ngb016-sensitive-data-logging.js';
import { ngb017 } from './ngb017-sensitive-data-in-urls.js';
import { ngb018 } from './ngb018-hardcoded-frontend-secrets.js';
import { ngb019 } from './ngb019-unsafe-csp-trusted-types.js';
import { ngb020 } from './ngb020-sensitive-ssr-transfer-cache.js';

/** Rules NGB016–NGB020. */
export const rules: SecurityRule[] = [ngb016, ngb017, ngb018, ngb019, ngb020];
