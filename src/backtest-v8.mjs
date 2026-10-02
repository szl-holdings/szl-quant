// SPDX-License-Identifier: Apache-2.0
// Generation 8: context is read-only; decisions and fills stay inside the scored window.
import { evaluate } from './strategy.mjs';
import { makeBook, paperFill, markToMarket, toMicroUsd, microToUsdString, QTY } from './portfolio.mjs';

function validateReplay(series, params, costModel, startingCashUsd) {
  if (!Array.isArray(series) || series.length < 2) throw new Error('at least two ordered daily bars required');
  for (let i = 0; i < series.length; i++) {
    const row = series[i];
    if (!row || !Number.isSafeInteger(row.tMs) || Math.abs(row.tMs) > 8.64e15 ||
        !Number.isFinite(row.close) || row.close <= 0 ||
        (i > 0 && row.tMs - series[i - 1].tMs !== 86_400_000)) {
      throw new Error('replay requires finite positive prices and ordered daily timestamps without gaps');
    }
  }
  if (!params || !['momentumLookback', 'zWindow', 'volWindow'].every((key) => Number.isSafeInteger(params[key]) && params[key] >= 1) ||
      !Number.isFinite(params.zEntry) || params.zEntry < 0 || !Number.isFinite(params.positionFraction) ||
      params.positionFraction <= 0 || params.positionFraction > 1) throw new Error('invalid replay parameters');
  if (!Number.isFinite(startingCashUsd) || startingCashUsd <= 0) throw new Error('invalid starting cash');
  if (!costModel || !Number.isFinite(costModel.feeBps) || costModel.feeBps < 0 ||
      !Number.isFinite(costModel.slippageBps) || costModel.slippageBps < 0 ||
      costModel.feeBps + costModel.slippageBps >= 10000) throw new Error('invalid modeled costs');
}

export function replaySeriesV8(series, params, costModel, startingCashUsd = 10000, bounds = {}) {
  validateReplay(series, params, costModel, startingCashUsd);
  const scoreStartIndex = bounds.scoreStartIndex ?? 0;
  const scoreEndIndex = bounds.scoreEndIndex ?? series.length;
  if (!Number.isSafeInteger(scoreStartIndex) || !Number.isSafeInteger(scoreEndIndex) ||
      scoreStartIndex < 0 || scoreEndIndex > series.length || scoreStartIndex >= scoreEndIndex) throw new Error('invalid score boundaries');
  const warmup = Math.max(params.momentumLookback, params.zWindow, params.volWindow) + 2;
  const firstDecisionIndex = Math.max(warmup, scoreStartIndex);
  const book = makeBook({ startingCashUsd, costModel });
  const equityCurve = [{ index: scoreStartIndex, equityUsd: microToUsdString(book.cashMicro) }];
  const fills = [], roundTrips = [];
  let entry = null, modeledCostMicro = 0n;
  for (let i = firstDecisionIndex; i < scoreEndIndex - 1; i++) {
    const action = evaluate(series.slice(0, i + 1), params).action;
    const nextBar = series[i + 1];
    const atIso = new Date(nextBar.tMs).toISOString();
    const before = book.cashMicro;
    let fill;
    if (action === 'ENTER_LONG' && entry === null) {
      const notional = Math.floor(Number(microToUsdString(book.cashMicro)) * params.positionFraction * 100) / 100;
      if (notional >= 10) fill = paperFill(book, { asset: 'ASSET', side: 'BUY', notionalUsd: notional, price: nextBar.close, atIso, reason: 'ENTER_LONG @ next close (no lookahead)' });
    } else if (action === 'EXIT_LONG' && entry !== null) {
      fill = paperFill(book, { asset: 'ASSET', side: 'SELL', qtyE9: book.positions.ASSET.qtyE9, price: nextBar.close, atIso, reason: 'EXIT_LONG @ next close (no lookahead)' });
    }
    if (fill) {
      const delta = book.cashMicro - before;
      const gross = BigInt(fill.qtyE9) * toMicroUsd(nextBar.close) / QTY;
      const cost = fill.side === 'BUY' ? -delta - gross : gross - delta;
      modeledCostMicro += cost;
      const recorded = { side: fill.side, decisionIndex: i, fillIndex: i + 1, atIso, price: String(nextBar.close),
                         qtyE9: fill.qtyE9, cashDeltaMicro: delta.toString(), modeledCostMicro: cost.toString() };
      fills.push(recorded);
      if (fill.side === 'BUY') entry = recorded;
      else {
        const net = BigInt(entry.cashDeltaMicro) + delta;
        roundTrips.push({ entryFillIndex: entry.fillIndex, exitFillIndex: i + 1, netPnlMicro: net.toString(), win: net > 0n });
        entry = null;
      }
    }
    const mark = markToMarket(book, { ASSET: nextBar.close }, atIso);
    equityCurve.push({ index: i + 1, equityUsd: mark.equityUsd });
  }
  const last = series[scoreEndIndex - 1];
  const finalMark = markToMarket(book, { ASSET: last.close }, new Date(last.tMs).toISOString());
  const finalEquity = Number(finalMark.equityUsd);
  let peak = startingCashUsd, drawdown = 0;
  for (const row of equityCurve) {
    const equity = Number(row.equityUsd);
    peak = Math.max(peak, equity);
    drawdown = Math.max(drawdown, (peak - equity) / peak);
  }
  const eligible = firstDecisionIndex < scoreEndIndex - 1;
  return { replayVersion: 8, state: eligible ? 'REPLAYED' : 'INSUFFICIENT_WARMUP',
    boundaries: { contextStartIndex: 0, scoreStartIndex, scoreEndIndex,
                  firstDecisionIndex: eligible ? firstDecisionIndex : null, firstFillIndex: eligible ? firstDecisionIndex + 1 : null },
    finalEquityUsd: finalEquity, totalReturn: finalEquity / startingCashUsd - 1, maxDrawdown: drawdown,
    nTrades: fills.length, nRoundTrips: roundTrips.length,
    winRate: roundTrips.length ? roundTrips.filter((trip) => trip.win).length / roundTrips.length : null,
    winRateBasis: 'NET_AFTER_MODELED_FEES_AND_SLIPPAGE',
    winRateNote: roundTrips.length < 10 ? `only ${roundTrips.length} round trips — win rate is statistically weak evidence` : undefined,
    modeledCostUsd: microToUsdString(modeledCostMicro), openAtEnd: entry !== null, fills, roundTrips, equityCurve };
}

export function walkForwardV8(series, grid, costModel, isFraction = 0.7, startingCashUsd = 10000) {
  if (!Number.isFinite(isFraction) || isFraction <= 0 || isFraction >= 1 || !Array.isArray(grid) || grid.length === 0) throw new Error('invalid walk-forward split or grid');
  const splitIndex = Math.floor(series.length * isFraction);
  if (splitIndex < 1 || splitIndex >= series.length) throw new Error('split has an empty window');
  const results = grid.map((params) => ({ params,
    inSample: replaySeriesV8(series, params, costModel, startingCashUsd, { scoreStartIndex: 0, scoreEndIndex: splitIndex }),
    outOfSample: replaySeriesV8(series, params, costModel, startingCashUsd, { scoreStartIndex: splitIndex, scoreEndIndex: series.length }) }));
  return { replayVersion: 8, splitIndex, inSampleBars: splitIndex, outOfSampleBars: series.length - splitIndex,
           populationSize: grid.length, cherryPickNote: 'ALL declared configs reported; no selection on out-of-sample results.', results };
}
