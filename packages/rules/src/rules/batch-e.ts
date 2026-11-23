import type { SecurityRule } from '@ngbastion/plugin-api';
import { ngb091 } from './ngb091-untrusted-code-in-privileged-workflow.js';
import { ngb092 } from './ngb092-excessive-workflow-permissions.js';
import { ngb093 } from './ngb093-unpinned-third-party-action.js';
import { ngb094 } from './ngb094-workflow-expression-injection.js';
import { ngb095 } from './ngb095-untrusted-artifact-in-privileged-workflow.js';
import { ngb096 } from './ngb096-exposed-dev-server.js';
import { ngb097 } from './ngb097-package-manager-tls-disabled.js';
import { ngb098 } from './ngb098-tls-validation-disabled.js';
import { ngb099 } from './ngb099-untrusted-federation-remote.js';
import { ngb100 } from './ngb100-untrusted-import-map.js';

/** Milestone batch E rules, in ID order. */
export const rules: SecurityRule[] = [ngb091, ngb092, ngb093, ngb094, ngb095, ngb096, ngb097, ngb098, ngb099, ngb100];
