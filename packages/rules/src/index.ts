import type { SecurityRule } from '@ngbastion/plugin-api';
import { ngb001 } from './rules/ngb001-unsafe-html-trust-bypass.js';
import { ngb002 } from './rules/ngb002-unsafe-resource-trust-bypass.js';
import { ngb003 } from './rules/ngb003-dom-injection-sink.js';
import { ngb004 } from './rules/ngb004-dynamic-code-execution.js';
import { ngb005 } from './rules/ngb005-untrusted-script-loading.js';
import { rules as crossWindow } from './rules/group-cross-window.js';
import { rules as navigationStorage } from './rules/group-navigation-storage.js';
import { rules as dataConfigSsr } from './rules/group-data-config-ssr.js';
import { ngb021 } from './rules/ngb021-disabled-xsrf-protection.js';
import { ngb022 } from './rules/ngb022-client-controlled-authorization.js';
import { ngb023 } from './rules/ngb023-missing-oauth-state.js';
import { ngb024 } from './rules/ngb024-weakened-oauth-config.js';
import { ngb025 } from './rules/ngb025-auth-cookie-from-javascript.js';
import { ngb026 } from './rules/ngb026-untrusted-request-destination.js';
import { ngb027 } from './rules/ngb027-sensitive-dom-attributes.js';
import { ngb028 } from './rules/ngb028-sensitive-global-objects.js';
import { ngb029 } from './rules/ngb029-sensitive-navigation-state.js';
import { ngb030 } from './rules/ngb030-permissive-referrer-policy.js';
import { ngb031 } from './rules/ngb031-sensitive-cache-storage.js';
import { ngb032 } from './rules/ngb032-service-worker-user-cache.js';
import { ngb033 } from './rules/ngb033-window-open-without-noopener.js';
import { ngb034 } from './rules/ngb034-untrusted-postmessage-target.js';
import { ngb035 } from './rules/ngb035-untrusted-method-dispatch.js';
import { ngb036 } from './rules/ngb036-prototype-pollution.js';
import { ngb037 } from './rules/ngb037-regex-injection.js';
import { ngb038 } from './rules/ngb038-sensitive-form-target.js';
import { ngb039 } from './rules/ngb039-jsonp-request.js';
import { ngb040 } from './rules/ngb040-plaintext-transport.js';

/** All built-in rules, ordered by ID. */
export const builtinRules: SecurityRule[] = [
  ngb001, ngb002, ngb003, ngb004, ngb005, ...crossWindow, ...navigationStorage, ...dataConfigSsr,
  ngb021, ngb022, ngb023, ngb024, ngb025, ngb026, ngb027, ngb028, ngb029, ngb030,
  ngb031, ngb032, ngb033, ngb034, ngb035, ngb036, ngb037, ngb038, ngb039, ngb040,
];

export { classifyName, looksLikePan, words } from './shared/sensitivity.js';
export { docsUrl } from './shared/meta.js';
