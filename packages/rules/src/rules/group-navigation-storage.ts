import type { SecurityRule } from '@ngbastion/plugin-api';
import { ngb011 } from './ngb011-untrusted-redirect.js';
import { ngb012 } from './ngb012-unsafe-navigation-scheme.js';
import { ngb013 } from './ngb013-credential-forwarding.js';
import { ngb014 } from './ngb014-insecure-token-storage.js';
import { ngb015 } from './ngb015-payment-data-persistence.js';

/** Rules NGB011–NGB015. */
export const rules: SecurityRule[] = [ngb011, ngb012, ngb013, ngb014, ngb015];
