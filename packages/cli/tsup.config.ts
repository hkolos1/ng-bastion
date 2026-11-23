import { defineConfig } from 'tsup';

export default defineConfig({
  entry: ['src/index.ts', 'src/html-renderer.ts', 'src/bin.ts', 'src/config.ts'],
  format: ['esm'],
  dts: { entry: ['src/index.ts', 'src/html-renderer.ts', 'src/config.ts'] },
  clean: true,
  sourcemap: true,
  target: 'node22',
});
