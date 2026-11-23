import { createRequire } from 'node:module';

// Read at runtime so `changeset version` is the single source of truth.
// '../package.json' resolves from both src/ and the flat dist/ output.
export const VERSION: string = (createRequire(import.meta.url)('../package.json') as { version: string }).version;
