import type { SecurityRule } from '@ngbastion/plugin-api';
import { ngb006 } from './ngb006-wildcard-postmessage-origin.js';
import { ngb007 } from './ngb007-missing-origin-validation.js';
import { ngb008 } from './ngb008-unverified-message-source.js';
import { ngb009 } from './ngb009-unvalidated-message-payload.js';
import { ngb010 } from './ngb010-overly-permissive-iframe.js';

/** Rules NGB006–NGB010. */
export const rules: SecurityRule[] = [ngb006, ngb007, ngb008, ngb009, ngb010];
