import test from 'node:test';
import assert from 'node:assert/strict';
import { makeBook, paperFill } from '../src/portfolio.mjs';
import { buildBookBody } from '../src/book.mjs';

test('paper cost model rejects negative or non-finite modeled costs', () => {
  for (const costModel of [
    { feeBps: -1, slippageBps: 20 },
    { feeBps: 30, slippageBps: -1 },
    { feeBps: Infinity, slippageBps: 20 },
    { feeBps: 30, slippageBps: NaN },
  ]) {
    assert.throws(
      () => makeBook({ startingCashUsd: 1000, costModel }),
      /finite and nonnegative/,
    );
  }
});

test('paper cost model rejects a combined rate that can make sell price nonpositive', () => {
  assert.throws(
    () => makeBook({ startingCashUsd: 1000, costModel: { feeBps: 6000, slippageBps: 4000 } }),
    /below 10000 bps/,
  );
  assert.throws(
    () => makeBook({ startingCashUsd: 1000, costModel: { feeBps: 9000, slippageBps: 2000 } }),
    /below 10000 bps/,
  );
});

test('book snapshots admitted costs and every fill revalidates inherited state', () => {
  const declared = { feeBps: 30, slippageBps: 20 };
  const book = makeBook({ startingCashUsd: 1000, costModel: declared });

  declared.feeBps = -500;
  assert.deepEqual(book.costModel, { feeBps: 30, slippageBps: 20 });

  const fill = paperFill(book, {
    asset: 'X',
    side: 'BUY',
    notionalUsd: 100,
    price: 10,
    atIso: '2026-09-24T00:00:00.000Z',
    reason: 'regression',
  });
  assert.ok(Number(fill.modeledCostUsd) >= 0);

  // A resurrected/legacy book object does not pass through makeBook, so the
  // fill boundary itself must fail closed if its inherited config is invalid.
  book.costModel = { feeBps: -1, slippageBps: 0 };
  assert.throws(
    () => paperFill(book, {
      asset: 'X',
      side: 'BUY',
      notionalUsd: 10,
      price: 10,
      atIso: '2026-09-24T00:01:00.000Z',
      reason: 'invalid inherited config',
    }),
    /finite and nonnegative/,
  );
});

test('stateful book refuses an invalid inherited cost model even when no fill occurs', () => {
  const predecessor = buildBookBody({
    prevBook: null,
    decisions: [],
    runDir: '20260924T000000Z_run1',
    nowIso: '2026-09-24T00:00:00.000Z',
    allRunDirs: ['20260924T000000Z_run1'],
    config: {
      startingCashUsd: 1000,
      entryFractionBps: 1000,
      costModel: { feeBps: 30, slippageBps: 20 },
    },
  });

  predecessor.config.costModel.feeBps = -1;
  assert.throws(
    () => buildBookBody({
      prevBook: {
        runDir: '20260924T000000Z_run1',
        file: 'book_1.receipt.json',
        sha256: 'a'.repeat(64),
        body: predecessor,
      },
      decisions: [],
      runDir: '20260924T010000Z_run2',
      nowIso: '2026-09-24T01:00:00.000Z',
      allRunDirs: ['20260924T000000Z_run1', '20260924T010000Z_run2'],
    }),
    /finite and nonnegative/,
  );
});
