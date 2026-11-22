import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vitest/config';

const src = (p: string) => fileURLToPath(new URL(`./packages/${p}`, import.meta.url));
const alias = {
  '@ngbastion/plugin-api': src('plugin-api/src/index.ts'),
  '@ngbastion/config': src('config/src/index.ts'),
  '@ngbastion/core': src('core/src/index.ts'),
  '@ngbastion/rules': src('rules/src/index.ts'),
};

export default defineConfig({
  resolve: { alias },
  test: {
    testTimeout: 60_000,
    coverage: {
      provider: 'v8',
      include: ['packages/*/src/**/*.ts'],
      exclude: ['packages/*/src/**/*.d.ts', 'packages/cli/src/bin.ts'],
      reporter: ['text-summary', 'json-summary', 'text'],
    },
    projects: [
      { resolve: { alias }, test: { name: 'unit', include: ['packages/*/test/**/*.test.ts'] } },
      { resolve: { alias }, test: { name: 'integration', include: ['tests/integration/**/*.test.ts'] } },
      { resolve: { alias }, test: { name: 'compatibility', include: ['tests/compatibility/**/*.test.ts'] } },
    ],
  },
});
