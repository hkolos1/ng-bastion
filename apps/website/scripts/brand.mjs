// Generates the NgBastion brand assets into /assets/brand (run once; outputs are committed).
// The mark is a five-bastion star-fort trace (trace italienne) enclosing a terminal prompt.
import { mkdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import sharp from 'sharp';

const out = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../../assets/brand');
mkdirSync(out, { recursive: true });

// Palette matches the site's design tokens (src/styles.css): neutral base, violet primary, amber prompt.
const C = { slate: '#141417', steel: '#8b7cf8', amber: '#f0b45b', ink: '#5b47e0', stone: '#fafaf9', text: '#ececee', muted: '#a0a0ab' };

/** Star-fort outline centred at (cx, cy) with outer radius R. */
function fort(cx, cy, R) {
  const pts = [];
  for (let k = 0; k < 5; k++) {
    const t = -90 + k * 72;
    for (const [r, d] of [[0.6, -25], [0.8, -19], [1, 0], [0.8, 19], [0.6, 25]]) {
      const a = ((t + d) * Math.PI) / 180;
      pts.push(`${(cx + R * r * Math.cos(a)).toFixed(2)},${(cy + R * r * Math.sin(a)).toFixed(2)}`);
    }
  }
  return pts.join(' ');
}

const mark = ({ outline, fill, prompt, size = 64 }) => `
  <polygon points="${fort(size / 2, size / 2 + 1.5, size * 0.44)}" fill="${fill}" stroke="${outline}" stroke-width="${size / 20}" stroke-linejoin="miter"/>
  <path d="M${size * 0.36} ${size * 0.4} L${size * 0.5} ${size * 0.52} L${size * 0.36} ${size * 0.64}" fill="none" stroke="${prompt}" stroke-width="${size / 14}" stroke-linecap="round" stroke-linejoin="round"/>
  <path d="M${size * 0.55} ${size * 0.66} H${size * 0.68}" stroke="${prompt}" stroke-width="${size / 14}" stroke-linecap="round"/>`;

const svg = (w, h, body, title) =>
  `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${w} ${h}" width="${w}" height="${h}" role="img" aria-label="${title}"><title>${title}</title>${body}</svg>\n`;

// Mark: themeable via currentColor for the outline; prompt in amber.
writeFileSync(path.join(out, 'logo-mark.svg'), svg(64, 64, mark({ outline: 'currentColor', fill: 'none', prompt: C.amber }), 'NgBastion'));
// Solid marks for fixed backgrounds.
writeFileSync(path.join(out, 'logo-mark-dark.svg'), svg(64, 64, mark({ outline: C.steel, fill: C.slate, prompt: C.amber }), 'NgBastion'));
writeFileSync(path.join(out, 'logo-mark-light.svg'), svg(64, 64, mark({ outline: C.ink, fill: C.stone, prompt: '#b7791f' }), 'NgBastion'));
writeFileSync(path.join(out, 'favicon.svg'), svg(64, 64, mark({ outline: C.steel, fill: C.slate, prompt: C.amber }), 'NgBastion'));

const wordmark = (color) => `<text x="76" y="44" font-family="'Geist', 'Inter', 'Helvetica Neue', Arial, sans-serif" font-size="33" font-weight="600" letter-spacing="-1" fill="${color}">NgBastion</text>`;
writeFileSync(path.join(out, 'logo-full-dark.svg'), svg(260, 64, mark({ outline: C.steel, fill: C.slate, prompt: C.amber }) + wordmark(C.text), 'NgBastion'));
// Neutral variant readable on light and dark backgrounds (e.g. GitHub README).
writeFileSync(path.join(out, 'logo-full.svg'), svg(260, 64, mark({ outline: '#7c6cf2', fill: C.slate, prompt: C.amber }) + wordmark('#7c6cf2'), 'NgBastion'));
writeFileSync(path.join(out, 'logo-full-light.svg'), svg(260, 64, mark({ outline: C.ink, fill: C.stone, prompt: '#b7791f' }) + wordmark('#18181b'), 'NgBastion'));

// Social preview 1280×640.
const social = svg(1280, 640, `
  <rect width="1280" height="640" fill="${C.slate}"/>
  <g opacity="0.12" stroke="${C.steel}" fill="none" stroke-width="2">
    <polygon points="${fort(1060, 330, 420)}"/><polygon points="${fort(1060, 330, 300)}"/>
  </g>
  <g transform="translate(96 120) scale(2.4)">${mark({ outline: C.steel, fill: C.slate, prompt: C.amber })}</g>
  <text x="96" y="370" font-family="'Geist', 'Inter', 'Helvetica Neue', Arial, sans-serif" font-size="92" font-weight="600" letter-spacing="-3" fill="${C.text}">NgBastion</text>
  <text x="98" y="438" font-family="'Helvetica Neue', Arial, sans-serif" font-size="38" fill="${C.muted}">Your Angular security stronghold.</text>
  <text x="98" y="540" font-family="Menlo, 'DejaVu Sans Mono', monospace" font-size="26" fill="${C.amber}">$ ngbastion scan</text>
  <text x="380" y="540" font-family="Menlo, 'DejaVu Sans Mono', monospace" font-size="26" fill="${C.muted}">local-first · type-aware data-flow · SARIF</text>`, 'NgBastion — Your Angular security stronghold.');
writeFileSync(path.join(out, 'social-preview.svg'), social);
await sharp(Buffer.from(social)).png().toFile(path.join(out, 'social-preview.png'));
await sharp(Buffer.from(svg(64, 64, mark({ outline: C.steel, fill: C.slate, prompt: C.amber }), 'NgBastion'))).resize(180, 180).png().toFile(path.join(out, 'apple-touch-icon.png'));
console.log(`brand assets written to ${out}`);
