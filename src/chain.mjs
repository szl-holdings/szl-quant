/**
 * chain.mjs — tamper-evident hash chain over the receipt ledger.
 *
 * The ledger branch is deliberately unprotected (append-only by
 * convention, not by force). Chain receipts turn that convention into
 * something checkable: every scheduled run seals its receipt files
 * (sha256 each) into a signed chain receipt that also pins the sha256 of
 * the PREVIOUS chain receipt's bytes. Rewriting or deleting any sealed
 * run — or any past chain link — breaks the chain where it happened.
 *
 * Genesis (seq 1) backfills: it seals every run dir that existed before
 * the chain was introduced, so the whole history is locked in from the
 * first link. If a later run's chain step ever fails, the next link
 * seals the orphaned dir too (covers = all currently-unsealed dirs).
 *
 * HONEST LIMIT (stated everywhere this ships): a hash chain cannot
 * detect wholesale deletion of the newest link(s) — head truncation.
 * External witnesses (GitHub Actions run logs, INDEX history in git)
 * cover that gap; the chain makes every OTHER rewrite loud.
 */
import { createHash } from 'node:crypto';
import { join } from 'node:path';

export const CHAIN_FILE_RE = /^chain_\d{4}\.receipt\.json$/;
const sha256Hex = (buf) => createHash('sha256').update(buf).digest('hex');

/**
 * Scan a ledger tree: run dirs (with sha256 of every non-chain .json),
 * existing chain receipts (bytes-hash + decoded body), and which dirs are
 * already sealed. IO is injected for testability.
 */
export function scanLedgerForChain(ledgerDir, { readdirSync, readFileSync }) {
  let dirents;
  try { dirents = readdirSync(ledgerDir, { withFileTypes: true }); }
  catch { return { runDirs: [], chains: [], prevChain: null, coveredDirs: new Set() }; }
  const dirs = dirents.filter((e) => e.isDirectory()).map((e) => e.name).sort();
  const runDirs = [];
  const chains = [];
  for (const dir of dirs) {
    const names = readdirSync(join(ledgerDir, dir), { withFileTypes: true })
      .filter((e) => e.isFile()).map((e) => e.name).sort();
    const content = [];
    for (const name of names) {
      const bytes = readFileSync(join(ledgerDir, dir, name));
      if (CHAIN_FILE_RE.test(name)) {
        let body = null;
        try {
          const env = JSON.parse(bytes.toString('utf8'));
          body = JSON.parse(Buffer.from(env.payload, 'base64').toString('utf8'))?.predicate?.summary ?? null;
        } catch { /* unreadable chain receipt: surfaces as seq null */ }
        chains.push({ runDir: dir, file: name, sha256: sha256Hex(bytes), seq: body?.seq ?? null, covers: body?.covers ?? [] });
      } else if (name.endsWith('.json')) {
        content.push({ name, sha256: sha256Hex(bytes) });
      }
    }
    runDirs.push({ dir, files: content });
  }
  chains.sort((a, b) => (a.seq ?? 0) - (b.seq ?? 0));
  const coveredDirs = new Set();
  for (const c of chains) for (const cov of c.covers ?? []) if (cov?.dir) coveredDirs.add(cov.dir);
  return { runDirs, chains, prevChain: chains.length ? chains[chains.length - 1] : null, coveredDirs };
}

/**
 * Build the next chain body (pure). Seals every currently-unsealed run
 * dir. Returns null when there is nothing new to seal (honest no-op).
 */
export function buildChainBody({ runDirs, prevChain, coveredDirs, nowIso }) {
  const uncovered = runDirs.filter((r) => !(coveredDirs?.has?.(r.dir)));
  if (uncovered.length === 0) return null;
  if (prevChain && !Number.isInteger(prevChain.seq)) {
    throw new Error('previous chain receipt has no readable seq — refusing to fork the chain (fail closed)');
  }
  const seq = prevChain ? prevChain.seq + 1 : 1;
  const covers = uncovered.map(({ dir, files }) => ({ dir, files }));
  return {
    kind: 'szl-quant-chain',
    v: 1,
    seq,
    generatedAtIso: nowIso,
    prev: prevChain ? { runDir: prevChain.runDir, file: prevChain.file, sha256: prevChain.sha256 } : null,
    covers,
    coverage: { dirs: covers.length, files: covers.reduce((a, c) => a + c.files.length, 0) },
    note: prevChain
      ? 'links to prev chain receipt by sha256 of its bytes; seals all unsealed run dirs'
      : 'GENESIS — backfills every pre-chain run dir so the whole history is locked from the first link',
    limits: 'head truncation (deleting the newest link wholesale) is not detectable by the chain alone; external witnesses (Actions logs, git history of INDEX.md) cover that gap',
  };
}
