/// <reference types="vitest" />
import { readFileSync } from 'node:fs';
import { defineConfig } from 'vite';
import analog from '@analogjs/platform';
import tailwindcss from '@tailwindcss/vite';

/** Every route is pre-rendered (SSG). The list is produced by scripts/generate.mjs from real content. */
function prerenderRoutes(): string[] {
  try {
    return JSON.parse(readFileSync(new URL('./src/generated/routes.json', import.meta.url), 'utf8')) as string[];
  } catch {
    throw new Error('src/generated/routes.json is missing: run `node scripts/generate.mjs` first');
  }
}

export default defineConfig(({ mode }) => ({
  build: { target: ['es2022'] },
  resolve: { mainFields: ['module'] },
  plugins: [
    analog({
      ssr: true,
      static: true,
      prerender: mode === 'test' ? undefined : { routes: async () => prerenderRoutes() },
    }),
    tailwindcss(),
  ],
  test: {
    globals: true,
    environment: 'jsdom',
    setupFiles: ['src/test-setup.ts'],
    include: ['src/**/*.spec.ts'],
    reporters: ['default'],
  },
}));
