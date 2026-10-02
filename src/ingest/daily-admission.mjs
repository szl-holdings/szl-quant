// SPDX-License-Identifier: Apache-2.0
// Admit daily UTC price samples, retaining an explicit trailing live-snapshot exclusion.
export function admitDailySamples(prices, observedAtMs = Date.now()) {
  if (!Array.isArray(prices) || prices.length < 2 || !Number.isSafeInteger(observedAtMs)) throw new Error('invalid daily sample input');
  const rows = prices.map((sample) => {
    if (!Array.isArray(sample) || sample.length !== 2 || !Number.isSafeInteger(sample[0]) ||
        Math.abs(sample[0]) > 8.64e15 || sample[0] > observedAtMs ||
        !Number.isFinite(sample[1]) || sample[1] <= 0) throw new Error('malformed or future daily sample');
    return { tMs: sample[0], close: sample[1] };
  });
  const excludedSnapshots = [];
  const last = rows.at(-1), previous = rows.at(-2);
  if (last.tMs % 86400000 !== 0 && last.tMs > previous.tMs && last.tMs < previous.tMs + 86400000) {
    excludedSnapshots.push({ index: rows.length - 1, tMs: last.tMs, reason: 'TRAILING_INTRADAY_SNAPSHOT_NOT_A_DAILY_UTC_SAMPLE' });
    rows.pop();
  }
  if (rows.length < 2 || rows.some((row, index) => row.tMs % 86400000 !== 0 || (index > 0 && row.tMs - rows[index - 1].tMs !== 86400000))) {
    throw new Error('daily UTC samples are unordered, duplicated, gapped or irregular');
  }
  return { series: rows, rawCount: prices.length, admittedCount: rows.length, excludedSnapshots, observedAtMs,
    rule: 'DAILY_UTC_SAMPLES_V1_NO_INTERPOLATION_OR_SOURCE_STITCHING' };
}
