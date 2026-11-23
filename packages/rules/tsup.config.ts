import { defineConfig } from 'tsup';

export default defineConfig({
  entry: ['src/index.ts', 'src/snippet.ts'],
  format: ['esm'],
  dts: true,
  clean: true,
  sourcemap: true,
  target: 'node22',
});
