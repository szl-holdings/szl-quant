/**
 * sft-export.test.mjs — the receipts→SFT exporter is deterministic,
 * fail-closed, and every published artifact verifies.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, writeFileSync, mkdirSync, cpSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { exportSft } from '../tools/sft-export.mjs';
import { verifyEnvelope } from '../src/dsse.mjs';
import { canonicalBytes } from '../src/canonical-json.mjs';
import { loadPublicKeyFromSpkiBase64 } from '../src/keys.mjs';
import { TRUST_CEILING } from '../src/canon.mjs';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const sha256 = (buf) => createHash('sha256').update(buf).digest('hex');

function enginePub() {
  const pub = JSON.parse(readFileSync(join(ROOT, 'keys/engine_pubkey.json'), 'utf8'));
  return loadPublicKeyFromSpkiBase64(pub.publicKeySpkiBase64);
}

/** Minimal repo fixture: copies the real receipts + archives so tampering is isolated. */
function fixtureRepo() {
  const dir = mkdtempSync(join(tmpdir(), 'sftfix-'));
  mkdirSync(join(dir, 'receipts'), { recursive: true });
  mkdirSync(join(dir, 'data/datasets'), { recursive: true });
  cpSync(join(ROOT, 'receipts'), join(dir, 'receipts'), { recursive: true, filter: (s) => !s.includes('signal_') && !s.includes('session_') });
  cpSync(join(ROOT, 'data/datasets'), join(dir, 'data/datasets'), { recursive: true });
  cpSync(join(ROOT, 'keys'), join(dir, 'keys'), { recursive: true });
  return dir;
}

test('sft-export: deterministic — two runs produce byte-identical JSONL', () => {
  const a = exportSft({ repoRoot: ROOT, outDir: mkdtempSync(join(tmpdir(), 'sfta-')) });
  const b = exportSft({ repoRoot: ROOT, outDir: mkdtempSync(join(tmpdir(), 'sftb-')) });
  assert.ok(a.rows > 1000, `expected >1000 rows, got ${a.rows}`);
  assert.equal(a.manifest.jsonlSha256, b.manifest.jsonlSha256);
  for (const k of ['ENTER_LONG', 'EXIT_LONG', 'HOLD', 'ABSTAIN']) {
    assert.ok(a.counts[k] > 0, `no ${k} rows — dataset would be unbalanced/dishonest about coverage`);
  }
});

test('sft-export: every row respects the trust ceiling and carries full provenance', () => {
  const out = mkdtempSync(join(tmpdir(), 'sftc-'));
  const res = exportSft({ repoRoot: ROOT, outDir: out });
  const lines = readFileSync(res.jsonlPath, 'utf8').trim().split('\n');
  assert.equal(lines.length, res.rows);
  const knownDatasetShas = new Set(res.manifest.sources.map((s) => s.datasetSha256));
  const knownReceiptShas = new Set(res.manifest.sources.map((s) => s.receiptSha256));
  for (const line of lines) {
    const row = JSON.parse(line);
    const a = JSON.parse(row.messages[2].content);
    if (a.conviction != null) assert.ok(a.conviction <= TRUST_CEILING, `conviction ${a.conviction} > ceiling`);
    assert.ok(knownDatasetShas.has(row.provenance.datasetSha256), 'row cites unknown dataset sha');
    assert.ok(knownReceiptShas.has(row.provenance.receiptSha256), 'row cites unknown receipt sha');
    assert.ok(Number.isInteger(row.provenance.barIndex));
  }
});

test('sft-export: provenance receipt shas match the actual receipt file bytes', () => {
  const out = mkdtempSync(join(tmpdir(), 'sftd-'));
  const res = exportSft({ repoRoot: ROOT, outDir: out });
  for (const s of res.manifest.sources) {
    const got = sha256(readFileSync(join(ROOT, s.receiptFile)));
    assert.equal(got, s.receiptSha256, `${s.receiptFile}: manifest sha mismatch`);
  }
});

test('sft-export: tampered dataset archive → export fails closed, zero rows written', () => {
  const dir = fixtureRepo();
  // flip one byte inside one archive
  const arch = join(dir, 'data/datasets');
  const first = readFileSync(join(ROOT, 'receipts/backtest_BTC_365d.receipt.json'));
  const stmt = JSON.parse(Buffer.from(JSON.parse(first.toString()).payload, 'base64').toString());
  const sha = stmt.predicate.summary.dataset.sha256;
  const p = join(arch, `${sha}.json`);
  const bytes = readFileSync(p);
  const evil = Buffer.from(bytes);
  evil[evil.length - 5] = evil[evil.length - 5] === 0x31 ? 0x32 : 0x31;
  writeFileSync(p, evil);
  assert.throws(
    () => exportSft({ repoRoot: dir, outDir: join(dir, 'sft') }),
    /hash mismatch|not canonical/i,
  );
});

test('sft-export: forged source receipt (bad signature) → refused, fail closed', () => {
  const dir = fixtureRepo();
  const f = join(dir, 'receipts/backtest_BTC_365d.receipt.json');
  const env = JSON.parse(readFileSync(f, 'utf8'));
  // forge: inflate a number inside the payload without re-signing
  const stmt = JSON.parse(Buffer.from(env.payload, 'base64').toString());
  stmt.predicate.summary.walkForward.results[0].outOfSample.totalReturn = 9.99;
  env.payload = Buffer.from(JSON.stringify(stmt)).toString('base64');
  writeFileSync(f, JSON.stringify(env, null, 2));
  assert.throws(
    () => exportSft({ repoRoot: dir, outDir: join(dir, 'sft') }),
    /does NOT verify|fail closed/i,
  );
});

test('sft-export: committed sft artifacts verify — manifest sha, receipt signature, subject digest', () => {
  const jsonl = readFileSync(join(ROOT, 'sft/quant_sft_v1.jsonl'));
  const manifest = JSON.parse(readFileSync(join(ROOT, 'sft/quant_sft_v1.manifest.json'), 'utf8'));
  assert.equal(sha256(jsonl), manifest.jsonlSha256, 'committed JSONL does not match manifest pin');

  const env = JSON.parse(readFileSync(join(ROOT, 'sft/quant_sft_v1.manifest.receipt.json'), 'utf8'));
  const v = verifyEnvelope(env, enginePub());
  assert.equal(v.ok, true, `sft receipt signature invalid: ${v.reason}`);
  const stmt = JSON.parse(Buffer.from(env.payload, 'base64').toString());
  assert.equal(stmt.predicateType, 'https://szl.holdings/quant/sft-export/v1');
  const digest = stmt.subject[0].digest.sha256;
  assert.equal(digest, sha256(canonicalBytes(manifest)), 'subject digest does not pin the committed manifest');
});

test('sft-export: ABSTAIN rows are genuine engine abstentions', () => {
  const out = mkdtempSync(join(tmpdir(), 'sfte-'));
  const res = exportSft({ repoRoot: ROOT, outDir: out });
  const lines = readFileSync(res.jsonlPath, 'utf8').trim().split('\n');
  let abstains = 0;
  for (const line of lines) {
    const row = JSON.parse(line);
    const a = JSON.parse(row.messages[2].content);
    if (a.action === 'ABSTAIN') {
      abstains++;
      assert.match(a.note, /abstaining/i);
      assert.equal(row.provenance.derivation, 'deterministic-abstain-drill');
    }
  }
  assert.equal(abstains, res.counts.ABSTAIN);
});
