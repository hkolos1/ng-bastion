import type { SecurityRule } from '@ngbastion/plugin-api';
import { ngb051 } from './ngb051-mismatched-sanitization-context.js';
import { ngb052 } from './ngb052-unsafe-custom-sanitizer.js';
import { ngb053 } from './ngb053-runtime-template-compilation.js';
import { ngb054 } from './ngb054-untrusted-base-url.js';
import { ngb055 } from './ngb055-ssr-cross-request-state.js';
import { ngb056 } from './ngb056-passthrough-trusted-types-policy.js';
import { ngb057 } from './ngb057-missing-oidc-nonce.js';
import { ngb058 } from './ngb058-id-token-as-bearer.js';
import { ngb059 } from './ngb059-jwt-decoded-without-verification.js';
import { ngb060 } from './ngb060-untrusted-oauth-redirect-uri.js';

/** Milestone batch A rules, in ID order. */
export const rules: SecurityRule[] = [ngb051, ngb052, ngb053, ngb054, ngb055, ngb056, ngb057, ngb058, ngb059, ngb060];
