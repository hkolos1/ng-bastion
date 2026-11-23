import { randomUUID } from 'node:crypto';
import { closeSync, openSync, linkSync, readFileSync, renameSync, rmSync, unlinkSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { Ajv } from 'ajv';
import { FINGERPRINT_VERSION } from '@ngbastion/core';
import type { Snapshot } from './comparison.js';

export class ReportingError extends Error {}
const require = createRequire(import.meta.url);
const validate = new Ajv().compile<Snapshot>(require('../schema/baseline-v1.json'));

export function parseSnapshot(value: unknown): Snapshot {
  const header = value as Partial<Snapshot> | null;
  if (header?.schemaVersion !== 1) throw new ReportingError('Unsupported baseline schema. Expected schemaVersion 1.');
  if (header.fingerprintVersion !== FINGERPRINT_VERSION) throw new ReportingError('Incompatible fingerprint version. Create a fresh baseline with this scanner.');
  if (!validate(value)) throw new ReportingError('Invalid baseline: ' + validate.errors?.map(e => e.instancePath + ' ' + e.message).join(', '));
  const ids = new Set(value.findings.map(f => f.fingerprint));
  if (ids.size !== value.findings.length || value.inactive.some(id => ids.has(id))) throw new ReportingError('Invalid baseline: duplicate finding identity');
  return value;
}

export function readSnapshot(file: string): Snapshot {
  try {
    return parseSnapshot(JSON.parse(readFileSync(file, 'utf8')));
  } catch (error) {
    throw new ReportingError(`Cannot read baseline ${file}: ${(error as Error).message}`);
  }
}

export function writeSnapshot(file: string, value: Snapshot, previous?: Snapshot) {
  const temp = file + '.' + randomUUID() + '.tmp';
  const lock = file + '.lock';
  let locked = false;
  try {
    closeSync(openSync(lock, 'wx', 0o600));
    locked = true;
    if (previous && JSON.stringify(readSnapshot(file)) !== JSON.stringify(previous)) {
      throw new Error('baseline changed during the scan. Repeat the comparison');
    }
    writeFileSync(temp, JSON.stringify(value, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
    if (previous) renameSync(temp, file);
    else linkSync(temp, file); // Atomic create without replacing an existing baseline.
  } catch (error) {
    throw new ReportingError(`Cannot ${previous ? 'update' : 'create'} baseline ${file}: ${(error as Error).message}`);
  } finally {
    if (locked) unlinkSync(lock);
    rmSync(temp, { force: true });
  }
}
