/** Explicit publication-availability fixtures; preserve the admitted strict history contract. */
import test from 'node:test';
import assert from 'node:assert/strict';
import { scoreSignal, buildTrackRecord } from '../src/track.mjs';
const T0 = Date.parse('2026-01-01T00:00:00.000Z');
const DAY = 86400000;
const statement = { subject: [{ name: 'szl-quant/signal/T/2026-01-01T00:00:00.000Z' }] };
const point = (day, close = 100, extra = {}) => ({ tMs: T0 + day * DAY, close, ...extra });
const score = (series, now = T0 + 8 * DAY) => scoreSignal({ statement, series, nowMs: now, horizons: [7], source: 'SYNTHETIC_REGRESSION' });

test('publication: completed event with future availability is not an observed outcome', () => {
  const result = score([point(0), point(7, 90, { availableAtMs: T0 + 9 * DAY })]);
  assert.equal(result.outcomes.h7d.label, 'UNAVAILABLE');
  assert.equal(result.outcomes.h7d.code, 'OUTCOME_GAP');
});
test('publication: availability exactly at the as-of clock becomes observable', () => {
  const result = score([point(0), point(7, 90, { availableAtMs: T0 + 9 * DAY })], T0 + 9 * DAY);
  assert.equal(result.outcomes.h7d.label, 'MEASURED');
  assert.ok(Math.abs(result.outcomes.h7d.forwardReturn + 0.1) < 1e-12);
});
test('publication: an unavailable baseline is not reused from the later outcome', () => {
  const result = score([point(0, 100, { availableAtMs: T0 + 20 * DAY }), point(7, 90)]);
  assert.equal(result.outcomes.h7d.code, 'BASELINE_GAP');
});
test('publication: malformed availability fails the retained strict input contract', () => {
  for (const value of [NaN, Infinity, null, true, '2026-01-01', -1, T0 - 1]) {
    const result = score([point(0, 100, { availableAtMs: value }), point(7, 90)]);
    assert.equal(result.outcomes.h7d.code, 'INVALID_AVAILABILITY');
  }
});
test('publication: unavailable outcome price changes cannot alter earlier results', () => {
  const make = (close) => score([point(0), point(7, close, { availableAtMs: T0 + 20 * DAY })]);
  for (const price of [1, 100, 100000000000]) assert.deepEqual(make(price), make(90));
});
test('publication: absent availability preserves legacy semantics without claiming vintages', () => {
  const result = score([point(0), point(7, 90)]);
  assert.equal(result.outcomes.h7d.label, 'MEASURED');
  assert.equal(result.outcomes.h7d.horizonAnchor, 'decision-clock');
});
test('publication: current strict ordering and caller input are preserved', () => {
  const rows = [point(7, 90), point(0)];
  const original = structuredClone(rows);
  assert.equal(score(rows).outcomes.h7d.code, 'INVALID_HISTORY');
  assert.deepEqual(rows, original);
});
test('publication: full report retains withheld outcomes and the capital HOLD', () => {
  const allowed = { file: 'synthetic', statement: { ...statement, predicate: { decision: {
    verdict: 'ALLOWED', proposedAction: 'ENTER_LONG', asset: { address: 'T', symbol: 'T' },
  } } } };
  const result = buildTrackRecord({ verified: [allowed], excluded: [],
    histories: { T: { ok: true, series: [point(0), point(7, 900, { availableAtMs: T0 + 20 * DAY })], dataset: { source: 'SYNTHETIC_REGRESSION' } } },
    nowMs: T0 + 8 * DAY, horizons: [7] });
  assert.equal(result.population.total, 1);
  assert.equal(result.aggregates.h7d.nRealized, 0);
  assert.equal(result.aggregates.h7d.nGaps, 1);
  assert.equal(result.aggregates.h7d.hitRate, null);
  assert.equal(result.researchQualification.state, 'HOLD');
  assert.equal(result.researchQualification.pointInTimeVintagesVerified, false);
  assert.equal(result.researchQualification.capitalAdmission, false);
});
