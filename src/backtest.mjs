/**
 * backtest.mjs — MEASURED backtests on real history.
 *
 * Honesty rules enforced here:
 *  - the input dataset is real venue history (REPORTED feed), pinned by
 *    sha256 in the receipt; the RESULT of replaying it is MEASURED;
 *  - the FULL parameter population is reported — every config in the grid,
 *    no cherry-picking, sorted by nothing (declaration order);
 *  - costs are MODELED and applied to every simulated fill;
 *  - walk-forward split: parameters may only be preferred on the IN-SAMPLE
 *    window; the OUT-OF-SAMPLE window is replayed once per config and
 *    reported for all of them;
 *  - no annualized Sharpe theater: we report per-window total return,
 *    max drawdown, trade count, win rate — with n so small the receipt
 *    says so explicitly.
 */
import { evaluate } from './strategy.mjs';
import { makeBook, paperFill, markToMarket } from './portfolio.mjs';

/** Max drawdown over an equity curve (fractions of peak). */
function maxDrawdown(equity) {
  let peak = -Infinity, mdd = 0;
  for (const e of equity) {
    peak = Math.max(peak, e);
    if (peak > 0) mdd = Math.max(mdd, (peak - e) / peak);
  }
  return mdd;
}

/**
 * Replay one asset's daily series through evaluate() with given params.
 * Decisions at close t are filled at close t+1 (no lookahead).
 * Returns summary + trade list. Deterministic.
 */
export function replaySeries(series, params, costModel, startingCashUsd = 10_000) {
  const book = makeBook({ startingCashUsd, costModel });
  const equity = [];
  let inPosition = false;
  const trades = [];

  const warmup = Math.max(params.momentumLookback, params.zWindow, params.volWindow) + 2;
  for (let i = warmup; i < series.length - 1; i++) {
    const window = series.slice(0, i + 1);
    const sig = evaluate(window, params);
    const nextBar = series[i + 1];
    const atIso = new Date(nextBar.tMs).toISOString();

    if (sig.action === 'ENTER_LONG' && !inPosition) {
      const cashUsd = Number(markToMarket(book, {}, atIso).cashUsd);
      const notional = Math.floor(cashUsd * params.positionFraction * 100) / 100;
      if (notional >= 10) {
        paperFill(book, { asset: 'ASSET', side: 'BUY', notionalUsd: notional, price: nextBar.close, atIso, reason: 'ENTER_LONG @ next close (no lookahead)' });
        inPosition = true;
        trades.push({ t: atIso, side: 'BUY', price: nextBar.close });
      }
    } else if (sig.action === 'EXIT_LONG' && inPosition) {
      const pos = book.positions.ASSET;
      if (pos.qtyE9 > 0n) {
        paperFill(book, { asset: 'ASSET', side: 'SELL', qtyE9: pos.qtyE9, price: nextBar.close, atIso, reason: 'EXIT_LONG @ next close (no lookahead)' });
        inPosition = false;
        trades.push({ t: atIso, side: 'SELL', price: nextBar.close });
      }
    }
    const mtm = markToMarket(book, { ASSET: series[i + 1].close }, atIso);
    if (mtm.equityUsd !== null) equity.push(Number(mtm.equityUsd));
  }

  // liquidation-free final mark
  const last = series[series.length - 1];
  const finalMark = markToMarket(book, { ASSET: last.close }, new Date(last.tMs).toISOString());
  const finalEquity = finalMark.equityUsd !== null ? Number(finalMark.equityUsd) : null;

  // win rate over round trips
  let wins = 0, roundTrips = 0;
  for (let i = 0; i + 1 < trades.length; i += 2) {
    if (trades[i].side === 'BUY' && trades[i + 1].side === 'SELL') {
      roundTrips++;
      if (trades[i + 1].price > trades[i].price) wins++;
    }
  }

  return {
    finalEquityUsd: finalEquity,
    totalReturn: finalEquity === null ? null : finalEquity / startingCashUsd - 1,
    maxDrawdown: equity.length ? maxDrawdown(equity) : null,
    nTrades: trades.length,
    nRoundTrips: roundTrips,
    winRate: roundTrips > 0 ? wins / roundTrips : null,
    winRateNote: roundTrips < 10 ? `only ${roundTrips} round trips — win rate is statistically weak evidence` : undefined,
    openAtEnd: inPosition,
  };
}

/**
 * Walk-forward backtest over a fixed, declared parameter grid.
 * Split: first `isFraction` of the series is IN-SAMPLE, rest OUT-OF-SAMPLE.
 * Returns results for the FULL population (both windows, every config).
 */
export function walkForward(series, grid, costModel, isFraction = 0.7) {
  const splitIdx = Math.floor(series.length * isFraction);
  const inSample = series.slice(0, splitIdx);
  const outSample = series.slice(splitIdx - 60 >= 0 ? splitIdx - 60 : 0); // carry warmup context
  const results = [];
  for (const params of grid) {
    results.push({
      params,
      inSample: replaySeries(inSample, params, costModel),
      outOfSample: replaySeries(outSample, params, costModel),
    });
  }
  return {
    splitIndex: splitIdx,
    inSampleBars: inSample.length,
    outOfSampleBars: series.length - splitIdx,
    populationSize: grid.length,
    cherryPickNote: 'ALL configs reported (full population). Selecting the best cell after the fact is multiple testing — see METHODOLOGY.md.',
    results,
  };
}
