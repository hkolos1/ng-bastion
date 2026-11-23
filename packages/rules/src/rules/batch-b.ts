import type { SecurityRule } from '@ngbastion/plugin-api';
import { ngb061 } from './ngb061-server-open-redirect.js';
import { ngb062 } from './ngb062-permissive-permissions-policy.js';
import { ngb063 } from './ngb063-dom-clobbering.js';
import { ngb064 } from './ngb064-untrusted-css-injection.js';
import { ngb065 } from './ngb065-broken-or-weak-cipher.js';
import { ngb066 } from './ngb066-sensitive-data-clipboard.js';
import { ngb067 } from './ngb067-sensitive-data-analytics.js';
import { ngb068 } from './ngb068-hardcoded-crypto-key.js';
import { ngb069 } from './ngb069-server-reflected-xss.js';
import { ngb070 } from './ngb070-timing-unsafe-comparison.js';

/** Milestone batch B rules, in ID order. */
export const rules: SecurityRule[] = [ngb061, ngb062, ngb063, ngb064, ngb065, ngb066, ngb067, ngb068, ngb069, ngb070];
