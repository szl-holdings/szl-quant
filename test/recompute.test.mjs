// Generation 7 — proof-of-recomputation drills.
// The independent verifier must re-derive every walk-forward number from the
// content-addressed dataset archive and fail CLOSED when it cannot: a valid
// signature alone is NOT enough to publish a MEASURED claim.
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { canonicalBytes } from '../src/canonical-json.mjs';
import { generateEngineKeypair, publicKeySpkiBase64, keyIdFromPublicKey } from '../src/keys.mjs';
import { signReceipt, PREDICATE } from '../src/receipts.mjs';
import { walkForward } from '../src/backtest.mjs';
import { datasetArchivePath, archiveDataset } from '../src/datasets.mjs';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const VERIFY = join(ROOT, 'verify', 'verify.mjs');

// Deterministic synthetic series (seeded LCG). MODELED fixture — clearly not
// market data; used only to drill the recompute machinery itself.
function syntheticSeries(n = 420) {
  let s = 42 >>> 0;
  const rnd = () => { s = (Math.imul(s, 1664525) + 1013904223) >>> 0; return s / 2 ** 32; };
  const out = [];
  let price = 100;
  const t0 = Date.UTC(2020, 0, 1);
  for (let i = 0; i < n; i++) {
    price = price * (1 + (rnd() - 0.5) * 0.06);
    out.push({ tMs: t0 + i * 86_400_000, close: price });
  }
  return out;
}

const GRID = [
  { momentumLookback: 14, zWindow: 20, zEntry: 1.0, volWindow: 30, positionFraction: 0.2 },
  { momentumLookback: 28, zWindow: 10, zEntry: 1.5, volWindow: 30, positionFraction: 0.2 },
];
const COST = { feeBps: 30, slippageBps: 20 };
const REPLAY = { isFraction: 0.7, startingCashUsd: 10_000 };

/** Build a temp repo-root with one signed backtest receipt + dataset archive. */
function makeFixture({ mutateSummary, omitArchive, skipDatasetFile, tamperDataset, badArchivePath } = {}) {
  const root = mkdtempSync(join(tmpdir(), 'g7-'));
  const receiptsDir = join(root, 'receipts');
  mkdirSync(receiptsDir, { recursive: true });
  const { privateKey, publicKey } = generateEngineKeypair();
  const pubPath = join(root, 'pub.json');
  writeFileSync(pubPath, JSON.stringify({
    kind: 'szl-quant-engine-pubkey', v: 1, alg: 'Ed25519',
    keyId: keyIdFromPublicKey(publicKey),
    publicKeySpkiBase64: publicKeySpkiBase64(publicKey),
  }, null, 2));
  const series = syntheticSeries();
  const bytes = canonicalBytes(series);
  const sha = createHash('sha256').update(bytes).digest('hex');
  if (!skipDatasetFile) {
    if (tamperDataset) {
      // write bytes that do NOT hash to the pinned sha (one close nudged)
      const tampered = series.map((r, i) => (i === 100 ? { ...r, close: r.close * 1.01 } : r));
      mkdirSync(join(root, 'data', 'datasets'), { recursive: true });
      writeFileSync(join(root, 'data', 'datasets', `${sha}.json`), canonicalBytes(tampered));
    } else {
      const a = archiveDataset(root, series, sha); // exercises the src writer too
      assert.equal(a.path, datasetArchivePath(sha));
    }
  }
  const wf = walkForward(series, GRID, COST, REPLAY.isFraction, REPLAY.startingCashUsd);
  const summary = {
    asset: { symbol: 'SYN', coinId: 'synthetic-fixture' },
    dataset: { source: 'synthetic-fixture (seeded LCG)', label: 'MODELED', n: series.length, sha256: sha },
    ...(omitArchive ? {} : {
      datasetArchive: {
        path: badArchivePath ?? datasetArchivePath(sha),
        scheme: 'content-addressed: filename = dataset.sha256 = sha256(canonical-json(series)); file content is exactly the hashed bytes',
        note: 'generation 7 test fixture',
      },
    }),
    method: {
      kind: 'walk-forward replay, decisions at close t filled at close t+1 (no lookahead)',
      costModel: { ...COST, label: 'MODELED' },
      grid: GRID,
      replay: { ...REPLAY, note: 'deterministic replay contract — the recomputation inputs (generation 7)' },
      label: 'MODELED', // synthetic fixture — NOT market history, honest label
      limits: 'test fixture',
    },
    walkForward: {
      splitIndex: wf.splitIndex,
      inSampleBars: wf.inSampleBars,
      outOfSampleBars: wf.outOfSampleBars,
      populationSize: wf.populationSize,
      cherryPickNote: wf.cherryPickNote,
      results: wf.results,
    },
  };
  if (mutateSummary) mutateSummary(summary);
  const { envelope } = signReceipt({
    predicateType: PREDICATE.backtest,
    subjectName: 'szl-quant/backtest/SYN/420d',
    subjectBody: summary,
    predicate: { summary },
    privateKey, publicKey,
  });
  writeFileSync(join(receiptsDir, 'backtest_SYN_420d.receipt.json'), JSON.stringify(envelope, null, 2) + '\n');
  return { root, receiptsDir, pubPath };
}

function runVerify(fx) {
  return spawnSync(process.execPath, [VERIFY, '--pubkey', fx.pubPath, '--dir', fx.receiptsDir, '--datasets-root', fx.root], { encoding: 'utf8' });
}

test('gen7: honest receipt recomputes bit-exact end-to-end', () => {
  const fx = makeFixture();
  const r = runVerify(fx);
  assert.equal(r.status, 0, r.stdout + r.stderr);
  assert.match(r.stdout, /recompute: OK — 2 grid cell\(s\) re-derived bit-exact from 420 archived bars/);
  assert.match(r.stdout, /1 backtest receipt\(s\) re-derived bit-exact, 0 skipped \(pre-gen7\), 0 FAILED/);
});

test('gen7: forged numbers under a VALID signature are caught by recompute', () => {
  const fx = makeFixture({
    mutateSummary: (s) => {
      const cell = s.walkForward.results[0].inSample;
      cell.totalReturn = (cell.totalReturn ?? 0) + 0.0123; // fabricated PnL
    },
  });
  const r = runVerify(fx);
  assert.equal(r.status, 1, r.stdout + r.stderr);
  assert.match(r.stdout, /PASS {2}/, 'signature itself must still verify — that is the point');
  assert.match(r.stdout, /RECOMPUTE FAIL: RECOMPUTE MISMATCH at \$\.results\[0\]\.inSample\.totalReturn/);
  assert.match(r.stdout, /a valid signature cannot rescue false numbers/);
});

test('gen7: tampered dataset bytes are caught by the content address', () => {
  const fx = makeFixture({ tamperDataset: true });
  const r = runVerify(fx);
  assert.equal(r.status, 1);
  assert.match(r.stdout, /RECOMPUTE FAIL: archived dataset bytes hash .* — dataset bytes TAMPERED or corrupted/);
});

test('gen7: declared-but-missing dataset archive fails closed', () => {
  const fx = makeFixture({ skipDatasetFile: true });
  const r = runVerify(fx);
  assert.equal(r.status, 1);
  assert.match(r.stdout, /RECOMPUTE FAIL: declared dataset archive MISSING .*fail closed/);
});

test('gen7: non-canonical archive path (traversal) is rejected', () => {
  const fx = makeFixture({ badArchivePath: 'data/datasets/../../evil.json' });
  const r = runVerify(fx);
  assert.equal(r.status, 1);
  assert.match(r.stdout, /anchored exact match required — no traversal, no aliases/);
});

test('gen7: pre-generation-7 receipt (no datasetArchive) gets an honest SKIP, not a fake pass', () => {
  const fx = makeFixture({ omitArchive: true });
  const r = runVerify(fx);
  assert.equal(r.status, 0, r.stdout + r.stderr);
  assert.match(r.stdout, /recompute: SKIP — pre-generation-7 receipt/);
  assert.match(r.stdout, /0 backtest receipt\(s\) re-derived bit-exact, 1 skipped \(pre-gen7\), 0 FAILED/);
});

test('gen7: archiveDataset refuses to write bytes that do not match the pinned sha', () => {
  const root = mkdtempSync(join(tmpdir(), 'g7a-'));
  const series = syntheticSeries(50);
  assert.throws(() => archiveDataset(root, series, 'ab'.repeat(32)), /refusing to archive a mislabeled dataset/);
  assert.equal(existsSync(join(root, 'data', 'datasets', `${'ab'.repeat(32)}.json`)), false, 'no partial write on refusal');
});

test('gen7: the repo\u2019s own committed receipts verify (recompute or honest skip, never FAIL)', () => {
  const r = spawnSync(process.execPath, [VERIFY, '--pubkey', join(ROOT, 'keys', 'engine_pubkey.json'), '--dir', join(ROOT, 'receipts')], { encoding: 'utf8' });
  assert.equal(r.status, 0, r.stdout + r.stderr);
  assert.doesNotMatch(r.stdout, /RECOMPUTE FAIL/);
});
