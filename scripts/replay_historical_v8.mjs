// SPDX-License-Identifier: Apache-2.0
// Additive replay evidence. Never overwrites or re-signs historical receipts.
import { createHash } from 'node:crypto';
import { readFileSync, readdirSync, writeFileSync, mkdirSync, openSync, closeSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { canonicalBytes } from '../src/canonical-json.mjs';
import { walkForward } from '../src/backtest.mjs';
import { admitDailySamples } from '../src/ingest/daily-admission.mjs';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const hash = (bytes) => createHash('sha256').update(bytes).digest('hex');
const output = resolve(process.argv[2] ?? join(root, 'audit/replay-v8-supersession.json'));
const verified = spawnSync(process.execPath, [join(root, 'verify/verify.mjs'), '--pubkey', join(root, 'keys/engine_pubkey.json'),
  '--dir', join(root, 'receipts'), '--datasets-root', root], { encoding: 'utf8' });
if (verified.status !== 0) throw new Error('historical signature/recomputation verification failed; supersession denied');
const report = { schema: 'szl.quant-replay-supersession/v1', replayVersion: 8,
  evidenceLabel: 'LOCAL_DETERMINISTIC_REPLAY_OF_ARCHIVED_REPORTED_MARKET_DATA',
  integrityKind: 'SHA256_NOT_SIGNATURE', promotionEffect: 'NONE', capitalAdmission: 'NOT_ADMITTED',
  limitations: 'Retrospective replay with modeled fill costs. No prospective prediction, external fills, model training or capital authorization.',
  historicalVerification: { exitCode: verified.status, logSha256: hash(Buffer.from(verified.stdout + verified.stderr)) },
  producerFiles: Object.fromEntries(['src/backtest-v8.mjs', 'src/strategy.mjs', 'src/portfolio.mjs', 'src/formulas.mjs', 'src/ingest/daily-admission.mjs', 'scripts/replay_historical_v8.mjs', 'verify/verify.mjs']
    .map((path) => [path, hash(readFileSync(join(root, path)))])), results: [] };
for (const name of readdirSync(join(root, 'receipts')).filter((name) => /^backtest_.*\.receipt\.json$/.test(name)).sort()) {
  const bytes = readFileSync(join(root, 'receipts', name));
  const envelope = JSON.parse(bytes);
  const summary = JSON.parse(Buffer.from(envelope.payload, 'base64')).predicate.summary;
  const dataset = readFileSync(join(root, summary.datasetArchive.path));
  if (hash(dataset) !== summary.dataset.sha256) throw new Error('dataset pin mismatch');
  const result = { historicalReceipt: name, historicalReceiptSha256: hash(bytes),
    datasetSha256: hash(dataset), historicalReplayVersion: summary.method.replay?.version ?? 7,
    historicalResults: summary.walkForward, supersessionReason: 'generation-7 warmup permitted pre-split OOS fills; win rate used raw prices; drawdown omitted initial equity' };
  try {
    const rawRows = JSON.parse(dataset);
    const admission = admitDailySamples(rawRows.map((row) => [row.tMs, row.close]), rawRows.at(-1).tMs);
    const { series, ...admissionEvidence } = admission;
    result.dailyAdmission = admissionEvidence;
    result.admittedDatasetSha256 = hash(canonicalBytes(series));
    result.correctedResults = walkForward(series, summary.method.grid, summary.method.costModel,
      summary.method.replay.isFraction, summary.method.replay.startingCashUsd);
    result.state = 'REPLAYED';
  } catch (error) {
    result.state = 'BLOCKED_INVALID_V8_INPUT';
    result.reason = error.message;
  }
  report.results.push(result);
}
report.receiptSha256 = hash(canonicalBytes(report));
mkdirSync(dirname(output), { recursive: true });
// Exclusive creation is the authority; no earlier path-existence check can race it.
const descriptor = openSync(output, 'wx');
try {
  writeFileSync(descriptor, JSON.stringify(report, null, 2) + '\n');
} finally {
  closeSync(descriptor);
}
console.log(JSON.stringify({ output, replayed: report.results.filter((row) => row.state === 'REPLAYED').length,
  blocked: report.results.filter((row) => row.state !== 'REPLAYED').length, receiptSha256: report.receiptSha256, promotionEffect: report.promotionEffect }));
