// Generates the NgBastion brand assets into /assets/brand (run once; outputs are committed).
// The mark is a crenellated bastion shield split into two facets, with a terminal prompt chevron cut through it:
// fortress (battlements), defence (shield), Angular (faceted shield geometry) and developer tooling (the prompt).
import { mkdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import sharp from 'sharp';

const out = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../../assets/brand');
mkdirSync(out, { recursive: true });

// Electric Royal Blue identity (matches src/styles.css).
const C = { primary: '#315bff', accent: '#7290ff', deep: '#1f3fd1', bg: '#090b12', fg: '#f1f4ff', ink: '#0f1424', muted: '#a4abc0' };
// Dark backgrounds: light facet accent, shaded facet primary. Light backgrounds: one step deeper for contrast on white.
const ON_DARK = { lit: C.accent, shade: C.primary };
const ON_LIGHT = { lit: C.primary, shade: C.deep };

// 64×64 grid. Shield with three merlons over a tapered point; prompt chevron cut out with even-odd fill.
const SHIELD = 'M5 5H18V14H26V5H38V14H46V5H59L55 41L32 59L9 41Z';
// Chevron: 7-unit stroke, bounding box (22.5–41.5) centred on the shield's axis (x = 32).
const CHEVRON = 'M22.5 24H29.5L41.5 35L29.5 46H22.5L34.5 35Z';
const mark = ({ lit, shade }) => `
  <defs><clipPath id="ngb-lit"><rect width="32" height="64"/></clipPath></defs>
  <path fill="${shade}" fill-rule="evenodd" d="${SHIELD}${CHEVRON}"/>
  <path fill="${lit}" fill-rule="evenodd" clip-path="url(#ngb-lit)" d="${SHIELD}${CHEVRON}"/>`;

const svg = (w, h, body, title) =>
  `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${w} ${h}" width="${w}" height="${h}" role="img" aria-label="${title}"><title>${title}</title>${body}</svg>\n`;
const write = (name, content) => writeFileSync(path.join(out, name), content);

// Icon-only. The dark-background colours also hold up on white, so they double as the neutral mark and favicon.
write('logo-mark.svg', svg(64, 64, mark(ON_DARK), 'NgBastion'));
write('logo-mark-dark.svg', svg(64, 64, mark(ON_DARK), 'NgBastion'));
write('logo-mark-light.svg', svg(64, 64, mark(ON_LIGHT), 'NgBastion'));
write('favicon.svg', svg(64, 64, mark(ON_DARK), 'NgBastion'));

// Horizontal wordmark: "Ng" in the brand tint, "Bastion" in the foreground colour.
const FONT = `font-family="'Geist', 'Inter', 'Helvetica Neue', Arial, sans-serif" font-weight="600"`;
const wordmark = (ng, rest) => `<text x="76" y="44" ${FONT} font-size="33" letter-spacing="-1"><tspan fill="${ng}">Ng</tspan><tspan fill="${rest}">Bastion</tspan></text>`;
write('logo-full-dark.svg', svg(260, 64, mark(ON_DARK) + wordmark(C.accent, C.fg), 'NgBastion'));
write('logo-full-light.svg', svg(260, 64, mark(ON_LIGHT) + wordmark(C.primary, C.ink), 'NgBastion'));
// Neutral primary logo, readable on light and dark backgrounds (e.g. GitHub README).
write('logo-full.svg', svg(260, 64, mark(ON_DARK) + wordmark(C.primary, C.primary), 'NgBastion'));

// Social preview 1280×640.
const social = svg(1280, 640, `
  <defs><radialGradient id="glow" cx="0.8" cy="0.5" r="0.6"><stop offset="0" stop-color="${C.primary}" stop-opacity="0.18"/><stop offset="1" stop-color="${C.primary}" stop-opacity="0"/></radialGradient></defs>
  <rect width="1280" height="640" fill="${C.bg}"/>
  <rect width="1280" height="640" fill="url(#glow)"/>
  <g fill="none" stroke="${C.primary}" stroke-width="0.25" opacity="0.22">
    <path transform="translate(800 40) scale(9)" d="${SHIELD}"/>
    <path transform="translate(890 130) scale(6.2)" d="${SHIELD}"/>
  </g>
  <g transform="translate(96 112) scale(2.5)">${mark(ON_DARK)}</g>
  <text x="96" y="370" ${FONT} font-size="92" letter-spacing="-3"><tspan fill="${C.accent}">Ng</tspan><tspan fill="${C.fg}">Bastion</tspan></text>
  <text x="98" y="438" font-family="'Helvetica Neue', Arial, sans-serif" font-size="38" fill="${C.muted}">Your Angular security stronghold.</text>
  <text x="98" y="540" font-family="Menlo, 'DejaVu Sans Mono', monospace" font-size="26" fill="${C.accent}">$ ngbastion scan</text>
  <text x="380" y="540" font-family="Menlo, 'DejaVu Sans Mono', monospace" font-size="26" fill="${C.muted}">local-first · type-aware data-flow · SARIF</text>`, 'NgBastion — Your Angular security stronghold.');
write('social-preview.svg', social);
await sharp(Buffer.from(social)).png().toFile(path.join(out, 'social-preview.png'));

// Apple touch icon: opaque tile, mark at ~70% with padding.
const touch = svg(180, 180, `<rect width="180" height="180" fill="${C.bg}"/><g transform="translate(26 24) scale(2)">${mark(ON_DARK)}</g>`, 'NgBastion');
await sharp(Buffer.from(touch)).png().toFile(path.join(out, 'apple-touch-icon.png'));
console.log(`brand assets written to ${out}`);
