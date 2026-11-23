import type { SecurityRule } from '@ngbastion/plugin-api';
import { ngb071 } from './ngb071-service-worker-scope-expansion.js';
import { ngb072 } from './ngb072-service-worker-credential-forwarding.js';
import { ngb073 } from './ngb073-sql-injection.js';
import { ngb074 } from './ngb074-service-worker-unvalidated-cache.js';
import { ngb075 } from './ngb075-untrusted-worker-script.js';
import { ngb076 } from './ngb076-server-side-request-forgery.js';
import { ngb077 } from './ngb077-server-path-traversal.js';
import { ngb078 } from './ngb078-os-command-injection.js';
import { ngb079 } from './ngb079-server-template-injection.js';
import { ngb080 } from './ngb080-nosql-injection.js';

/** Milestone batch C rules, in ID order. */
export const rules: SecurityRule[] = [ngb071, ngb072, ngb073, ngb074, ngb075, ngb076, ngb077, ngb078, ngb079, ngb080];
