/**
 * datasets.mjs — content-addressed archive of backtest input datasets
 * (generation 7: proof-of-recomputation).
 *
 * The backtest receipt has always pinned sha256(canonical-json(series)).
 * Archiving those exact bytes at data/datasets/<sha256>.json turns the pin
 * into something anyone can USE: the independent verifier re-derives every
 * walk-forward number from the archived bytes and requires bit-exact
 * agreement. A valid signature is no longer enough to publish a MEASURED
 * claim — the numbers must actually recompute.
 *
 * Honesty rules:
 *  - the file content IS the hashed content (no wrapper, no metadata) so
 *    the filename ↔ bytes relation is checkable with sha256sum alone;
 *  - collisions on write fail LOUDLY if existing bytes differ (that would
 *    mean a sha256 break or a bug — never silently overwrite);
 *  - archiving REPORTED feed bytes does not upgrade their label: the input
 *    stays REPORTED, only the replay over it is MEASURED.
 */
import { createHash } from 'node:crypto';
import { mkdirSync, writeFileSync, readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { canonicalBytes } from './canonical-json.mjs';

export const DATASETS_DIR = join('data', 'datasets');

/** Repo-relative archive path for a dataset sha (the receipt records this). */
export function datasetArchivePath(sha256) {
  if (!/^[0-9a-f]{64}$/.test(sha256)) throw new Error('dataset sha256 must be 64 lowercase hex chars');
  return `${DATASETS_DIR}/${sha256}.json`;
}

/**
 * Archive a dataset's canonical bytes under rootDir. Verifies the bytes
 * hash to `expectedSha256` (the value pinned in the receipt) — refuses to
 * write anything whose name would lie about its content.
 * Returns { path (repo-relative), bytes, existed }.
 */
export function archiveDataset(rootDir, series, expectedSha256) {
  const bytes = canonicalBytes(series);
  const sha = createHash('sha256').update(bytes).digest('hex');
  if (sha !== expectedSha256) {
    throw new Error(`dataset bytes hash ${sha.slice(0, 16)}… ≠ receipt-pinned ${String(expectedSha256).slice(0, 16)}… — refusing to archive a mislabeled dataset`);
  }
  const rel = datasetArchivePath(sha);
  const abs = join(rootDir, rel);
  mkdirSync(join(rootDir, DATASETS_DIR), { recursive: true });
  if (existsSync(abs)) {
    const prev = readFileSync(abs);
    if (!prev.equals(bytes)) {
      throw new Error(`archive collision at ${rel}: existing bytes differ from content hashing to the same name — refusing to overwrite (investigate immediately)`);
    }
    return { path: rel, bytes: bytes.length, existed: true };
  }
  writeFileSync(abs, bytes);
  return { path: rel, bytes: bytes.length, existed: false };
}
