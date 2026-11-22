import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';
import sitemap from '@astrojs/sitemap';

const SITE = 'https://ngbastion.dev';

export default defineConfig({
  site: SITE,
  trailingSlash: 'always',
  integrations: [
    starlight({
      title: 'NgBastion',
      description: 'Angular-aware, local-first security analysis: type-aware data-flow tracing from untrusted sources to dangerous sinks.',
      logo: { light: '../../assets/brand/logo-mark-light.svg', dark: '../../assets/brand/logo-mark-dark.svg', alt: 'NgBastion' },
      favicon: '/favicon.svg',
      customCss: ['./src/styles/fonts.css', './src/styles/starlight.css'],
      head: [
        { tag: 'meta', attrs: { property: 'og:image', content: `${SITE}/brand/social-preview.png` } },
        { tag: 'meta', attrs: { property: 'og:image:width', content: '1280' } },
        { tag: 'meta', attrs: { property: 'og:image:height', content: '640' } },
        { tag: 'meta', attrs: { name: 'twitter:card', content: 'summary_large_image' } },
        { tag: 'meta', attrs: { name: 'twitter:image', content: `${SITE}/brand/social-preview.png` } },
        { tag: 'link', attrs: { rel: 'apple-touch-icon', href: '/brand/apple-touch-icon.png' } },
      ],
      sidebar: [
        {
          label: 'Getting started',
          items: [
            { label: 'What is NgBastion?', slug: 'docs' },
            { label: 'Installation and local setup', slug: 'docs/getting-started/installation' },
            { label: 'First scan', slug: 'docs/getting-started/first-scan' },
            { label: 'Reading findings', slug: 'docs/getting-started/reading-findings' },
            { label: 'Project compatibility', slug: 'docs/getting-started/compatibility' },
          ],
        },
        { label: 'CLI reference', slug: 'docs/cli-reference' },
        { label: 'Configuration', slug: 'docs/configuration' },
        { label: 'Security engine', slug: 'docs/security-engine' },
        { label: 'Reports', slug: 'docs/reports' },
        { label: 'Plugin API', slug: 'docs/plugin-api' },
        { label: 'CI/CD', slug: 'docs/ci-cd' },
        { label: 'Limitations', slug: 'docs/limitations' },
        {
          label: 'Security rules',
          collapsed: true,
          items: [{ autogenerate: { directory: 'rules' } }],
        },
        {
          label: 'Project',
          items: [
            { label: 'Contributing', slug: 'docs/contributing' },
            { label: 'Security policy', slug: 'docs/security-policy' },
            { label: 'Changelog', slug: 'changelog' },
            { label: 'Playground', link: '/playground/' },
          ],
        },
      ],
    }),
    sitemap(),
  ],
});
