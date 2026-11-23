import type { SecurityRule } from '@ngbastion/plugin-api';
import { ngb081 } from './ngb081-permissive-cors-credentials.js';
import { ngb082 } from './ngb082-spoofable-client-ip.js';
import { ngb083 } from './ngb083-cross-site-websocket-hijacking.js';
import { ngb084 } from './ngb084-session-not-regenerated.js';
import { ngb085 } from './ngb085-error-details-to-client.js';
import { ngb086 } from './ngb086-static-password-salt.js';
import { ngb087 } from './ngb087-weak-password-work-factor.js';
import { ngb088 } from './ngb088-weak-asymmetric-key-size.js';
import { ngb089 } from './ngb089-truncated-authentication-tag.js';
import { ngb090 } from './ngb090-ignored-signature-verification.js';

/** Milestone batch D rules, in ID order. */
export const rules: SecurityRule[] = [ngb081, ngb082, ngb083, ngb084, ngb085, ngb086, ngb087, ngb088, ngb089, ngb090];
