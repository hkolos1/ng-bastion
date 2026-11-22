import { defineRule, type RuleFinding } from '@ngbastion/plugin-api';
import { assessWrite, storageWrites } from '../shared/storage.js';

export const ngb014 = defineRule({
  meta: {
    id: 'NGB014',
    name: 'Insecure token storage',
    category: 'sensitive-data',
    defaultSeverity: 'high',
    cwe: ['CWE-922'],
    docs: {
      description:
        'Reports authentication or session credentials (access/refresh/ID tokens, JWTs, session IDs, API keys, passwords) written to browser-accessible persistent storage: `localStorage`, `sessionStorage` and IndexedDB object stores. Evidence comes from the storage key, the stored value\'s name, its type, and names along its data flow.',
      rationale:
        'Anything in Web Storage or IndexedDB is readable by every script running in the origin. A single XSS bug or compromised third-party script can exfiltrate long-lived tokens, which then work from the attacker\'s machine. This is a design concern rather than a vulnerability by itself.',
      patterns: [
        '`localStorage.setItem(key, value)`, `sessionStorage.setItem(…)`, `localStorage.token = v`, `localStorage["token"] = v`',
        'IndexedDB `objectStore.put(value, key)` / `add(value, key)` on `IDBObjectStore`',
        'Key evidence: constant keys (including `const TOKEN_KEY = "access_token"`) classified by head noun (`access_token`, `jwt`, `refreshToken`, `sessionId`, `apiKey`)',
        'Value evidence: identifier/property names (`res.accessToken`), object literal keys (`JSON.stringify({ token })`), declared type properties, and names along the traced data flow',
        'Not reported: CSRF/XSRF tokens, metadata (`tokenExpiry`, `tokenType`), push/device/pagination tokens, opaque payment tokens, hashed or masked values',
      ],
      limitations: [
        'Name-based evidence: credentials stored under neutral names (`localStorage.setItem("a", x)` with an untyped `x`) are not detected.',
        'Storage wrappers from libraries (ngx-webstorage, localForage, idb) are not modeled.',
        'Cookies set from JavaScript are not covered by this rule.',
      ],
      falsePositives: [
        'Short-lived, audience-restricted tokens may be an accepted trade-off; document it with an exception and an expiry date.',
      ],
      remediation:
        'Keep session credentials in `HttpOnly`, `Secure`, `SameSite` cookies set by the server, or hold access tokens only in memory and refresh them via an HttpOnly refresh cookie (backend-for-frontend pattern).',
      example: {
        unsafe: `this.http.post<{ accessToken: string }>('/api/login', creds)
  .subscribe(res => localStorage.setItem('access_token', res.accessToken));`,
        safe: `// Server sets: Set-Cookie: session=…; HttpOnly; Secure; SameSite=Strict
this.http.post('/api/login', creds, { withCredentials: true }).subscribe();`,
      },
      references: [{ title: 'OWASP HTML5 Security — Local Storage', url: 'https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html#local-storage' }],
    },
  },
  analyze(ctx) {
    const findings: RuleFinding[] = [];
    for (const w of storageWrites(ctx, { cookies: false })) {
      const a = assessWrite(ctx, w, 'credential');
      if (!a) continue;
      findings.push({
        node: w.node,
        message: `Credential-like data is stored in ${w.store}${w.key ? ` under '${w.key}'` : ''}; it is readable by any script running in the page.`,
        confidence: a.confidence,
        severity: w.persistent ? 'high' : 'medium',
        evidenceKind: a.keyEvidence && a.valueEvidence ? 'pattern' : 'heuristic',
        evidence: a.evidence,
      });
    }
    return findings;
  },
});
