import js from '@eslint/js';
import tseslint from 'typescript-eslint';

export default tseslint.config(
  {
    ignores: ['**/dist/**', '**/node_modules/**', '**/coverage/**', '**/.astro/**', 'examples/**', 'tests/fixtures/**', 'apps/website/public/**', 'apps/website/playground-fixtures/**'],
  },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    // Node.js build / benchmark scripts.
    files: ['**/*.mjs'],
    languageOptions: {
      globals: { process: 'readonly', console: 'readonly', URL: 'readonly', performance: 'readonly', Buffer: 'readonly', setTimeout: 'readonly' },
    },
  },
  {
    rules: {
      '@typescript-eslint/no-unused-vars': ['error', { argsIgnorePattern: '^_', varsIgnorePattern: '^_' }],
      '@typescript-eslint/consistent-type-imports': 'error',
      'no-constant-condition': ['error', { checkLoops: false }],
    },
  },
);
