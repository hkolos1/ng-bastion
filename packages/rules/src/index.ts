import type { SecurityRule } from '@ngbastion/plugin-api';
import { ngb001 } from './rules/ngb001-unsafe-html-trust-bypass.js';
import { ngb002 } from './rules/ngb002-unsafe-resource-trust-bypass.js';
import { ngb003 } from './rules/ngb003-dom-injection-sink.js';
import { ngb004 } from './rules/ngb004-dynamic-code-execution.js';
import { ngb005 } from './rules/ngb005-untrusted-script-loading.js';
import { rules as crossWindow } from './rules/group-cross-window.js';
import { rules as navigationStorage } from './rules/group-navigation-storage.js';
import { rules as dataConfigSsr } from './rules/group-data-config-ssr.js';

/** All built-in rules, ordered by ID. */
export const builtinRules: SecurityRule[] = [ngb001, ngb002, ngb003, ngb004, ngb005, ...crossWindow, ...navigationStorage, ...dataConfigSsr];

export { classifyName, looksLikePan, words } from './shared/sensitivity.js';
export { docsUrl } from './shared/meta.js';
