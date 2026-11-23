import type * as ts from 'typescript';
import { defineRule, type RuleFinding, type Severity, type SourceLocation } from '@ngbastion/plugin-api';
import { memberName, strip } from '../shared/common.js';
import { hostingHeaders } from '../shared/files.js';

/** Features that expose devices, payments, credentials or user data. */
const POWERFUL: Record<string, Severity> = {
  camera: 'medium', microphone: 'medium', geolocation: 'medium', payment: 'medium', 'display-capture': 'medium',
  usb: 'medium', serial: 'medium', hid: 'medium', bluetooth: 'medium', 'clipboard-read': 'medium',
  'publickey-credentials-get': 'medium', 'publickey-credentials-create': 'medium', 'identity-credentials-get': 'medium',
  'local-fonts': 'low', 'screen-wake-lock': 'low', 'xr-spatial-tracking': 'low', midi: 'low',
  accelerometer: 'low', gyroscope: 'low', magnetometer: 'low', 'ambient-light-sensor': 'low', 'clipboard-write': 'low',
};

/** `camera=*, geolocation=(self "https://maps.example")` (Permissions-Policy) or `camera *; geolocation 'self'` (Feature-Policy). */
export function wildcardFeatures(header: string, value: string): string[] {
  const legacy = /^feature-policy$/i.test(header);
  const out: string[] = [];
  for (const raw of value.split(legacy ? ';' : ',')) {
    const part = raw.trim();
    if (!part) continue;
    const [feature, allow] = legacy ? [part.split(/\s+/)[0]!, part.split(/\s+/).slice(1).join(' ')] : [part.split('=')[0]!.trim(), part.slice(part.indexOf('=') + 1)];
    const f = feature.toLowerCase();
    if (!Object.hasOwn(POWERFUL, f)) continue;
    // `*` alone or inside a list: `camera=*`, `camera=(*)`, `camera *`.
    if (/(^|[\s(])\*([\s)]|$)/.test(allow.trim())) out.push(f);
  }
  return out;
}

const HEADERS = ['Permissions-Policy', 'Feature-Policy'];

export const ngb062 = defineRule({
  meta: {
    id: 'NGB062',
    name: 'Permissive Permissions-Policy',
    category: 'security-config',
    defaultSeverity: 'low',
    cwe: ['CWE-250', 'CWE-1021'],
    docs: {
      description:
        "Reports `Permissions-Policy` (and legacy `Feature-Policy`) response headers that grant powerful browser features — camera, microphone, geolocation, payment, display capture, USB / serial / HID / Bluetooth, clipboard read, WebAuthn / FedCM credentials — to every origin with the `*` allowlist. Headers are read from hosting configs (`firebase.json`, `vercel.json`, `staticwebapp.config.json`, `_headers`) and from constant `setHeader()` / `set()` / `header()` calls in server code. Iframe `allow` attributes are covered by NGB010.",
      rationale:
        "`Permissions-Policy` is the page's ceiling for which origins may ever use a feature. With `camera=*` any cross-origin frame the page embeds — an ad, a widget, user-supplied embed content — can be granted the camera with an `allow` attribute, and a single injected iframe is enough to prompt for, or (if the user already granted your origin) silently use, the device. The default allowlist for these features is `self`; a wildcard only removes protection.",
      patterns: [
        '`Permissions-Policy: camera=*, geolocation=(*)` and `Feature-Policy: camera *` in hosting configs / `_headers`',
        "`res.setHeader('Permissions-Policy', 'payment=*')` (also `set`, `header`, `append`) with a constant value",
        'Medium severity for device, payment, capture and credential features; low for sensors, MIDI, wake lock, local fonts and clipboard write',
      ],
      limitations: [
        'Headers added by a CDN, reverse proxy or framework middleware outside the repository are not visible.',
        'A missing Permissions-Policy header is not reported (the browser defaults are restrictive).',
      ],
      falsePositives: [
        'Applications that deliberately delegate a feature to arbitrary third-party embeds (e.g. a video-conferencing marketplace) are reported; prefer listing the partner origins instead of `*`.',
      ],
      remediation:
        'Grant powerful features only to the origins that need them — `camera=(self "https://video.example.com")` — or disable unused ones completely (`camera=(), microphone=(), geolocation=()`).',
      example: {
        unsafe: `{ "key": "Permissions-Policy", "value": "camera=*, microphone=*, geolocation=*" }`,
        safe: `{ "key": "Permissions-Policy", "value": "camera=(self \\"https://video.example.com\\"), microphone=(), geolocation=()" }`,
      },
      references: [
        { title: 'MDN — Permissions-Policy', url: 'https://developer.mozilla.org/docs/Web/HTTP/Headers/Permissions-Policy' },
        { title: 'W3C — Permissions Policy', url: 'https://www.w3.org/TR/permissions-policy/' },
      ],
    },
  },
  analyze(ctx) {
    const findings: RuleFinding[] = [];
    const report = (location: SourceLocation | undefined, node: ts.Node | undefined, where: string, header: string, value: string) => {
      const features = wildcardFeatures(header, value);
      if (!features.length) return;
      const severity: Severity = features.some((f) => POWERFUL[f] === 'medium') ? 'medium' : 'low';
      findings.push({
        ...(location ? { location } : { node: node! }),
        message: `${where} grants ${features.join(', ')} to every origin (${header} allowlist *); any embedded cross-origin frame can be delegated these features.`,
        confidence: 'high',
        severity,
        evidenceKind: 'pattern',
        evidence: [`${header}: ${value}`],
      });
    };
    for (const header of HEADERS) {
      for (const h of hostingHeaders(ctx, header)) report(h.location, undefined, h.origin, header, h.value);
    }
    for (const call of ctx.index.calls) {
      const [k, v] = call.arguments;
      if (!k || !v || !['setHeader', 'set', 'header', 'append'].includes(memberName(ctx, strip(ctx, call.expression)) ?? '')) continue;
      const name = ctx.symbols.constantString(k);
      const value = ctx.symbols.constantString(v);
      const header = HEADERS.find((h) => h.toLowerCase() === name?.toLowerCase());
      if (header && value !== undefined) report(undefined, call, 'Server response', header, value);
    }
    return findings;
  },
});
