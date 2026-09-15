/** As-of regression fixtures. No network, signing, ledger writes, or trading. */
import test from 'node:test';
import assert from 'node:assert/strict';
import { scoreSignal, buildTrackRecord } from '../src/track.mjs';
const T0 = Date.parse('2026-01-01T00:00:00.000Z');
const DAY = 86400000;
const statement = { subject: [{ name: 'szl-quant/signal/T/2026-01-01T00:00:00.000Z' }] };
const point = (day, close = 100, extra = {}) => ({ tMs: T0 + day * DAY, close, ...extra });
const score = (series, now = T0 + DAY, horizons = [7]) => scoreSignal({ statement, series, nowMs: now, horizons, source: 'SYNTHETIC_REGRESSION' });

test('as-of: future provider rows cannot realize an unelapsed horizon', () => {
  const result = score([point(0), point(7, 900)]).outcomes.h7d;
  assert.equal(result.label, 'UNAVAILABLE');
  assert.match(result.note, /pending/);
  assert.equal(result.forwardReturn, undefined);
});

test('as-of: future price perturbations do not change earlier outputs', () => {
  const baseline = score([point(0), point(1, 110)]);
  for (const future of [point(7, 900), point(7, 0), point(7, NaN), point(7, Infinity)]) {
    assert.deepEqual(score([point(0), point(1, 110), future]), baseline);
  }
});

test('as-of: inclusive observation clock admits a completed known endpoint', () => {
  const result = score([point(0), point(7, 90)], T0 + 7 * DAY).outcomes.h7d;
  assert.equal(result.label, 'MEASURED');
  assert.ok(Math.abs(result.forwardReturn + 0.1) < 1e-12);
});

test('as-of: before signal time no future baseline is measurable', () => {
  const result = score([point(0), point(7, 90)], T0 - 1).outcomes.h7d;
  assert.equal(result.label, 'UNAVAILABLE');
  assert.match(result.note, /pending/);
});

test('as-of: supplied publication availability is enforced independently of event time', () => {
  const result = score([point(0), point(7, 90, { availableAtMs: T0 + 9 * DAY })], T0 + 8 * DAY).outcomes.h7d;
  assert.equal(result.label, 'UNAVAILABLE');
});

test('as-of: availability equal to cutoff becomes observable', () => {
  const result = score([point(0), point(7, 90, { availableAtMs: T0 + 9 * DAY })], T0 + 9 * DAY).outcomes.h7d;
  assert.equal(result.label, 'MEASURED');
});

test('as-of: duplicate timestamps are unavailable, not arbitrarily selected', () => {
  const result = score([point(0), point(0, 900), point(7, 90)], T0 + 8 * DAY).outcomes.h7d;
  assert.equal(result.label, 'UNAVAILABLE');
  assert.match(result.note, /duplicate/);
});

test('as-of: unordered observations produce the same result without mutating input', () => {
  const rows = [point(7, 90), point(0), point(1, 110)];
  const copy = structuredClone(rows);
  assert.deepEqual(score(rows, T0 + 8 * DAY), score([...rows].reverse(), T0 + 8 * DAY));
  assert.deepEqual(rows, copy);
});

for (const close of [0, -1, NaN, Infinity, true, '100']) {
  test(`as-of: invalid visible close ${String(close)} cannot produce a measured return`, () => {
    const result = score([point(0, close), point(7, 90)], T0 + 8 * DAY).outcomes.h7d;
    assert.equal(result.label, 'UNAVAILABLE');
    assert.match(result.note, /invalid historical close/);
  });
}

test('as-of: missing daily baseline is not backfilled with a later horizon close', () => {
  const result = score([point(7, 90)], T0 + 10 * DAY).outcomes.h7d;
  assert.equal(result.label, 'UNAVAILABLE');
  assert.match(result.note, /history gap/);
});

test('as-of: a later daily observation does not fill a missing horizon', () => {
  const result = score([point(0), point(9, 90)], T0 + 10 * DAY).outcomes.h7d;
  assert.equal(result.label, 'UNAVAILABLE');
  assert.match(result.note, /history gap/);
});

test('as-of: invalid availability timestamp is rejected', () => {
  const result = score([point(0), point(7, 90, { availableAtMs: T0 })], T0 + 8 * DAY).outcomes.h7d;
  assert.equal(result.label, 'UNAVAILABLE');
  assert.match(result.note, /availability/);
});

test('as-of: invalid scoring clock fails closed', () => {
  for (const now of [NaN, Infinity, '2026-01-01', true, -1]) {
    assert.equal(score([point(0), point(7, 90)], now).outcomes.h7d.label, 'UNAVAILABLE');
  }
});

test('as-of: invalid event timestamp fails closed', () => {
  const result = score([point(0), { tMs: NaN, close: 90 }], T0 + 8 * DAY).outcomes.h7d;
  assert.equal(result.label, 'UNAVAILABLE');
  assert.match(result.note, /timestamp/);
});

test('as-of: overflow cannot serialize an invented measured numeric return', () => {
  const result = score([point(0, Number.MIN_VALUE), point(7, Number.MAX_VALUE)], T0 + 8 * DAY).outcomes.h7d;
  assert.equal(result.label, 'UNAVAILABLE');
});

test('as-of: full report counts pending evidence instead of a fabricated win', () => {
  const allowed = { file: 'synthetic', statement: { ...statement, predicate: { decision: {
    verdict: 'ALLOWED', proposedAction: 'ENTER_LONG', asset: { address: 'T', symbol: 'T' },
  } } } };
  const result = buildTrackRecord({ verified: [allowed], excluded: [],
    histories: { T: { ok: true, series: [point(0), point(7, 900)], dataset: { source: 'SYNTHETIC_REGRESSION' } } },
    nowMs: T0 + DAY, horizons: [7] });
  assert.equal(result.population.total, 1);
  assert.equal(result.aggregates.h7d.nRealized, 0);
  assert.equal(result.aggregates.h7d.nPending, 1);
  assert.equal(result.aggregates.h7d.hitRate, null);
});
