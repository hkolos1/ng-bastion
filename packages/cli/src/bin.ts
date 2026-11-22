#!/usr/bin/env node
import { run } from './run.js';

run(process.argv.slice(2)).then(
  (code) => { process.exitCode = code; },
  (error: unknown) => {
    console.error(`ngbastion: unexpected error: ${error instanceof Error ? error.stack ?? error.message : String(error)}`);
    process.exitCode = 2;
  },
);
