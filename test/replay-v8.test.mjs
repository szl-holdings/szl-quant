// SPDX-License-Identifier: Apache-2.0
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { lambdaAggregate } from '../src/formulas.mjs';
import { replaySeries, walkForward } from '../src/backtest.mjs';
import { walkForward as legacy } from '../src/backtest-legacy-v7.mjs';
import { canonicalBytes } from '../src/canonical-json.mjs';
import { archiveDataset } from '../src/datasets.mjs';
import { generateEngineKeypair, publicKeySpkiBase64, keyIdFromPublicKey } from '../src/keys.mjs';
import { signReceipt, PREDICATE } from '../src/receipts.mjs';
import { admitDailySamples } from '../src/ingest/daily-admission.mjs';

const params = { momentumLookback: 1, zWindow: 2, zEntry: 100, volWindow: 2, positionFraction: 1 };
const cost = { feeBps: 100, slippageBps: 100 };
const bars = (prices) => prices.map((close, i) => ({ tMs: Date.UTC(2020, 0, 1) + i * 86400000, close }));

test('daily admission explicitly excludes only a trailing intraday snapshot; gaps and future samples fail', () => {
  const raw = bars([100, 101, 102]).map((row) => [row.tMs, row.close]);
  const tail = [raw.at(-1)[0] + 1000, 105];
  const admitted = admitDailySamples([...raw, tail], tail[0]);
  assert.equal(admitted.series.length, 3);
  assert.equal(admitted.rawCount, 4);
  assert.equal(admitted.excludedSnapshots[0].index, 3);
  assert.equal(admitted.excludedSnapshots[0].reason, 'TRAILING_INTRADAY_SNAPSHOT_NOT_A_DAILY_UTC_SAMPLE');
  for (const input of [[raw[0], raw[2]], [raw[0], raw[0]], [raw[0], tail, raw[2]], [raw[0], [raw[1][0], NaN]]]) {
    assert.throws(() => admitDailySamples(input, tail[0]));
  }
  assert.throws(() => admitDailySamples(raw, raw[1][0]));
});

test('lambda rejects negative/nonfinite/sparse weights before any zero short circuit', () => {
  for (const weights of [[2, -1], [1, NaN], [Infinity, 1], [0, 0], [1, '1'], [1, true], Array(2), {}]) {
    assert.equal(lambdaAggregate([0.5, 0.1], weights), null);
    assert.equal(lambdaAggregate([0, 0.1], weights), null);
  }
  assert.equal(lambdaAggregate([0, NaN], [1, 1]), null);
  assert.equal(lambdaAggregate([0, 0.5], [0, 1]), 0.5);
  assert.equal(lambdaAggregate([0, 0.5], [1, 0]), 0);
  assert.equal(lambdaAggregate([0.5, 0.5], [Number.MAX_VALUE, Number.MAX_VALUE]), 0.5);
});

test('OOS starts with fresh cash; carried context cannot trade before its split', () => {
  const series = bars(Array.from({ length: 120 }, (_, i) => 100 + i));
  const current = walkForward(series, [params], cost, 0.7);
  assert.equal(current.splitIndex, 84);
  const oos = current.results[0].outOfSample;
  assert.deepEqual(oos.equityCurve[0], { index: 84, equityUsd: '10000.000000' });
  assert.equal(oos.boundaries.firstDecisionIndex, 84);
  assert.equal(oos.boundaries.firstFillIndex, 85);
  assert.ok(oos.fills.every((fill) => fill.decisionIndex >= 84 && fill.fillIndex >= 85));
  assert.ok(current.results[0].inSample.fills.every((fill) => fill.fillIndex < 84));
  assert.notEqual(oos.totalReturn, legacy(series, [params], cost, 0.7).results[0].outOfSample.totalReturn);
});

test('higher raw exit price can be a net loss and initial fill costs count as drawdown', () => {
  const replay = replaySeries(bars([90, 92, 94, 96, 98, 100, 99, 101]), params, cost);
  assert.equal(replay.nRoundTrips, 1);
  assert.equal(replay.fills[0].price, '100');
  assert.equal(replay.fills[1].price, '101');
  assert.equal(replay.winRate, 0);
  assert.ok(BigInt(replay.roundTrips[0].netPnlMicro) < 0n);
  assert.ok(replay.maxDrawdown >= 1 - 1 / 1.02);
  assert.equal(replay.winRateBasis, 'NET_AFTER_MODELED_FEES_AND_SLIPPAGE');
});

test('future bars cannot change earlier decisions, fills or equity', () => {
  const series = bars(Array.from({ length: 100 }, (_, i) => 100 + i));
  const other = series.map((row, i) => i < 80 ? row : { ...row, close: 50 + i });
  const a = replaySeries(series, params, cost), b = replaySeries(other, params, cost);
  assert.deepEqual(a.fills.filter((fill) => fill.fillIndex < 80), b.fills.filter((fill) => fill.fillIndex < 80));
  assert.deepEqual(a.equityCurve.filter((row) => row.index < 80), b.equityCurve.filter((row) => row.index < 80));
});

test('daily replay rejects malformed clocks, grids, costs and empty splits', () => {
  const series = bars([100, 101, 102, 103, 104, 105]);
  for (const bad of [series.map((row, i) => i === 2 ? { ...row, tMs: series[1].tMs } : row),
                     series.map((row, i) => i === 2 ? { ...row, close: NaN } : row),
                     series.map((row, i) => i === 2 ? { ...row, tMs: row.tMs + 1 } : row)]) {
    assert.throws(() => replaySeries(bad, params, cost));
  }
  for (const fraction of [0, 1, NaN, 0.01]) assert.throws(() => walkForward(series, [params], cost, fraction));
  assert.throws(() => replaySeries(series, { ...params, momentumLookback: -1 }, cost));
  assert.throws(() => replaySeries(series, params, { feeBps: -1, slippageBps: 0 }));
});

function verifyFixture(mutate) {
  const root = mkdtempSync(join(tmpdir(), 'quant-v8-'));
  mkdirSync(join(root, 'receipts'));
  const { privateKey, publicKey } = generateEngineKeypair();
  writeFileSync(join(root, 'pub.json'), JSON.stringify({ kind: 'szl-quant-engine-pubkey', v: 1, alg: 'Ed25519',
    keyId: keyIdFromPublicKey(publicKey), publicKeySpkiBase64: publicKeySpkiBase64(publicKey) }));
  const series = bars(Array.from({ length: 120 }, (_, i) => 100 + i));
  const sha = createHash('sha256').update(canonicalBytes(series)).digest('hex');
  const archived = archiveDataset(root, series, sha);
  const summary = { dataset: { n: series.length, sha256: sha, label: 'MODELED' }, datasetArchive: { path: archived.path },
    method: { grid: [params], costModel: cost, replay: { isFraction: 0.7, startingCashUsd: 10000, version: 8 }, label: 'MODELED' },
    walkForward: walkForward(series, [params], cost) };
  if (mutate) mutate(summary);
  const { envelope } = signReceipt({ predicateType: PREDICATE.backtest, subjectName: 'synthetic-v8-regression',
    subjectBody: summary, predicate: { summary }, privateKey, publicKey });
  writeFileSync(join(root, 'receipts/replay.json'), JSON.stringify(envelope));
  return spawnSync(process.execPath, ['verify/verify.mjs', '--pubkey', join(root, 'pub.json'), '--dir', join(root, 'receipts'), '--datasets-root', root], { encoding: 'utf8' });
}

test('standalone verifier recomputes v8; signatures cannot rescue boundary/net-result tampering', () => {
  const good = verifyFixture();
  assert.equal(good.status, 0, good.stdout + good.stderr);
  for (const mutate of [
    (s) => { s.walkForward.results[0].outOfSample.boundaries.scoreStartIndex--; },
    (s) => { s.walkForward.results[0].outOfSample.totalReturn += 0.1; },
    (s) => { s.method.replay.version = 9; },
    (s) => { s.walkForward.results[0].outOfSample.fills[0].cashDeltaMicro = '1'; },
  ]) {
    const bad = verifyFixture(mutate);
    assert.notEqual(bad.status, 0, bad.stdout + bad.stderr);
    assert.match(bad.stdout + bad.stderr, /RECOMPUTE MISMATCH|unsupported replay version/);
  }
});
