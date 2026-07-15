#!/usr/bin/env node
/**
 * quant.mjs — CLI for the SZL doctrine-governed quant engine.
 *
 *   node bin/quant.mjs backtest [--days 365] [--out receipts/]
 *   node bin/quant.mjs paper    [--out receipts/]
 *   node bin/quant.mjs verify   — delegates to verify/verify.mjs
 *
 * Advisory research system. PAPER ONLY. Not financial advice.
 */
import { mkdirSync, writeFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { fetchDailyHistory, RATE_DELAY_MS, sleep } from '../src/ingest/coingecko.mjs';
import { fetchSolanaPairs, deepestPairs } from '../src/ingest/dexscreener.mjs';
import { walkForward } from '../src/backtest.mjs';
import { decideLive, DEFAULT_PARAMS, DEFAULT_LIMITS } from '../src/engine.mjs';
import { makeLoopTaxLedger, runBoundedLoop } from '../src/ouroboros.mjs';
import { signReceipt, PREDICATE } from '../src/receipts.mjs';
import { ensureIdentity } from '../src/keys.mjs';
import { LABELS } from '../src/canon.mjs';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const KEY_PRIV = process.env.SZL_QUANT_KEY ?? join(ROOT, '.local-keys', 'engine_key.pem');
const KEY_PUB_JSON = join(ROOT, 'keys', 'engine_pubkey.json');

/** Backtest universe: real daily history via CoinGecko public API. */
const BACKTEST_UNIVERSE = [
  { coinId: 'bitcoin', symbol: 'BTC' },
  { coinId: 'ethereum', symbol: 'ETH' },
  { coinId: 'solana', symbol: 'SOL' },
  { coinId: 'bonk', symbol: 'BONK' },
];

/** Declared parameter grid — the FULL population is always reported. */
const GRID = [
  { momentumLookback: 14, zWindow: 20, zEntry: 1.0, volWindow: 30, positionFraction: 0.2 },
  { momentumLookback: 28, zWindow: 20, zEntry: 1.0, volWindow: 30, positionFraction: 0.2 },
  { momentumLookback: 56, zWindow: 20, zEntry: 1.0, volWindow: 30, positionFraction: 0.2 },
  { momentumLookback: 28, zWindow: 10, zEntry: 1.5, volWindow: 30, positionFraction: 0.2 },
  { momentumLookback: 28, zWindow: 30, zEntry: 0.5, volWindow: 30, positionFraction: 0.2 },
];

/** Live paper universe: Solana token mints (majors + liquid memecoins). */
const LIVE_TOKENS = [
  'So11111111111111111111111111111111111111112',  // wSOL
  'DezXAZ8z7PnrnRJjz3wXBoRgixCa6xjnB7YaB1pPB263', // BONK
  'EKpQGSJtjMFqKZ9KQanSqYXRcF8fBopzLHYxdM65zcjm', // WIF
  'JUPyiwrYJFskUPiHa7hkeR8VUtAeFoSYbKedZNsDvCN',  // JUP
];
/** CoinGecko ids for the same assets (history context for live decisions). */
const LIVE_HISTORY_IDS = {
  So11111111111111111111111111111111111111112: 'solana',
  DezXAZ8z7PnrnRJjz3wXBoRgixCa6xjnB7YaB1pPB263: 'bonk',
  EKpQGSJtjMFqKZ9KQanSqYXRcF8fBopzLHYxdM65zcjm: 'dogwifcoin',
  JUPyiwrYJFskUPiHa7hkeR8VUtAeFoSYbKedZNsDvCN: 'jupiter-exchange-solana',
};

const COST_MODEL = { feeBps: 30, slippageBps: 20 }; // MODELED, stated in receipts

function arg(name, dflt) {
  const i = process.argv.indexOf(`--${name}`);
  return i > -1 ? process.argv[i + 1] : dflt;
}

async function cmdBacktest() {
  const days = Number(arg('days', '365'));
  const outDir = arg('out', join(ROOT, 'receipts'));
  mkdirSync(outDir, { recursive: true });
  const keys = ensureIdentity(KEY_PRIV, KEY_PUB_JSON);
  console.log(`engine keyId=${keys.keyId} (pubkey committed at keys/engine_pubkey.json; private key NOT in repo)`);

  for (const { coinId, symbol } of BACKTEST_UNIVERSE) {
    console.log(`\n=== ${symbol} (${coinId}) — fetching ${days}d real history (coingecko public, REPORTED feed) ===`);
    const hist = await fetchDailyHistory(coinId, days);
    if (!hist.ok) {
      console.log(`  ${LABELS.UNAVAILABLE}: ${hist.unavailable.note} — no backtest for ${symbol} (fail closed, nothing invented)`);
      await sleep(RATE_DELAY_MS);
      continue;
    }
    console.log(`  dataset n=${hist.dataset.n} ${hist.dataset.firstIso} → ${hist.dataset.lastIso} sha256=${hist.dataset.sha256.slice(0, 16)}…`);
    const wf = walkForward(hist.series, GRID, COST_MODEL);
    const summary = {
      asset: { symbol, coinId },
      dataset: hist.dataset,                    // REPORTED feed, sha256-pinned
      method: {
        kind: 'walk-forward replay, decisions at close t filled at close t+1 (no lookahead)',
        costModel: { ...COST_MODEL, label: 'MODELED' },
        grid: GRID,
        label: 'MEASURED',                       // replay of real history
        limits: 'Daily bars only; long-only; no shorting/leverage; small-n win rates are weak evidence; multiple-testing risk disclosed (full population reported).',
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
    const { envelope } = signReceipt({
      predicateType: PREDICATE.backtest,
      subjectName: `szl-quant/backtest/${symbol}/${days}d`,
      subjectBody: summary,
      predicate: { summary },
      privateKey: keys.privateKey,
      publicKey: keys.publicKey,
    });
    const file = join(outDir, `backtest_${symbol}_${days}d.receipt.json`);
    writeFileSync(file, JSON.stringify(envelope, null, 2) + '\n');
    for (const r of wf.results) {
      const oos = r.outOfSample;
      console.log(`  L=${r.params.momentumLookback} zW=${r.params.zWindow} zE=${r.params.zEntry}  OOS ret=${oos.totalReturn === null ? 'n/a' : (oos.totalReturn * 100).toFixed(2) + '%'} mdd=${oos.maxDrawdown === null ? 'n/a' : (oos.maxDrawdown * 100).toFixed(1) + '%'} trades=${oos.nTrades} [MEASURED]`);
    }
    console.log(`  receipt → ${file}`);
    await sleep(RATE_DELAY_MS);
  }
}

async function cmdPaper() {
  const outDir = arg('out', join(ROOT, 'receipts'));
  mkdirSync(outDir, { recursive: true });
  const keys = ensureIdentity(KEY_PRIV, KEY_PUB_JSON);
  const sessionStartMs = Date.now();
  console.log(`live paper session @ ${new Date(sessionStartMs).toISOString()} keyId=${keys.keyId}`);

  const snap = await fetchSolanaPairs(LIVE_TOKENS);
  if (!snap.ok) {
    // Honest empty session — feed down means NO signals, and we SAY so.
    const summary = {
      session: new Date(sessionStartMs).toISOString(),
      feed: 'dexscreener',
      status: { label: 'UNAVAILABLE', note: snap.unavailable.note },
      signals: [],
      honestEmpty: 'feed unavailable — zero signals emitted (fail closed, nothing synthesized)',
    };
    const { envelope } = signReceipt({
      predicateType: PREDICATE.session,
      subjectName: `szl-quant/session/${new Date(sessionStartMs).toISOString()}`,
      subjectBody: summary,
      predicate: { summary },
      privateKey: keys.privateKey, publicKey: keys.publicKey,
    });
    const file = join(outDir, `session_${sessionStartMs}.receipt.json`);
    writeFileSync(file, JSON.stringify(envelope, null, 2) + '\n');
    console.log(`feed UNAVAILABLE (${snap.unavailable.note}) — honest empty session receipt → ${file}`);
    return;
  }

  const pairs = deepestPairs(snap.pairs);
  console.log(`dexscreener: ${snap.pairs.length} pairs → ${pairs.length} deepest-by-token [REPORTED]`);

  // History context (needed by strategy + vol gate) — serial, rate-honest.
  const histByAddr = {};
  for (const p of pairs) {
    const id = LIVE_HISTORY_IDS[p.baseAddress];
    if (!id) { histByAddr[p.baseAddress] = { ok: false, unavailable: { label: 'UNAVAILABLE', note: 'no history mapping for token' } }; continue; }
    histByAddr[p.baseAddress] = await fetchDailyHistory(id, 120);
    await sleep(RATE_DELAY_MS);
  }

  // Decision clock: taken AFTER all fetches so freshness measures true
  // snapshot age (fetch time), not fetch duration mistaken for skew.
  const nowMs = Date.now();

  // Ouroboros bounded loop over the decision batch: one step per asset,
  // loop-tax charged per decision, budget = assets + 2 headroom.
  const ledger = makeLoopTaxLedger({ budget: pairs.length + 2, taxPerStep: 1 });
  const decisions = [];
  const { trace } = runBoundedLoop({
    initialState: { i: 0 },
    step: (state) => {
      const pair = pairs[state.i];
      if (!pair) return { state, abort: true };
      const res = decideLive({ pair, history: histByAddr[pair.baseAddress], ledger, nowMs, keys });
      decisions.push(res);
      return { state: { i: state.i + 1 }, output: res.decision.verdict };
    },
    delta: (a, b) => Math.abs(b.i - a.i),
    config: { label: 'szl-quant.paper-batch', maxSteps: pairs.length + 1, ledger, convergenceThreshold: 0 },
  });

  for (const d of decisions) {
    const file = join(outDir, `signal_${d.decision.asset.symbol}_${nowMs}.receipt.json`);
    writeFileSync(file, JSON.stringify(d.envelope, null, 2) + '\n');
    console.log(`  ${d.decision.asset.symbol}: ${d.decision.proposedAction} → ${d.decision.verdict}${d.decision.blockedBy.length ? ` (blocked by: ${d.decision.blockedBy.join(', ')})` : ''} conviction=${d.decision.conviction ?? 'n/a'} → ${file}`);
  }

  const summary = {
    session: new Date(nowMs).toISOString(),
    feed: 'dexscreener [REPORTED] + coingecko history [REPORTED]',
    decisions: decisions.map((d) => ({ asset: d.decision.asset.symbol, action: d.decision.proposedAction, verdict: d.decision.verdict, blockedBy: d.decision.blockedBy })),
    ouroboros: { trace: { id: trace.id, label: trace.label, exitReason: trace.exitReason, stepsRun: trace.stepsRun, maxSteps: trace.maxSteps }, loopTax: { budget: ledger.budget, spent: ledger.spent, remaining: ledger.remaining } },
  };
  const { envelope } = signReceipt({
    predicateType: PREDICATE.session,
    subjectName: `szl-quant/session/${new Date(nowMs).toISOString()}`,
    subjectBody: summary,
    predicate: { summary },
    privateKey: keys.privateKey, publicKey: keys.publicKey,
  });
  const file = join(outDir, `session_${nowMs}.receipt.json`);
  writeFileSync(file, JSON.stringify(envelope, null, 2) + '\n');
  console.log(`session receipt (ouroboros trace: ${trace.exitReason}, loop-tax ${ledger.spent}/${ledger.budget}) → ${file}`);
}

const cmd = process.argv[2];
if (cmd === 'backtest') await cmdBacktest();
else if (cmd === 'paper') await cmdPaper();
else {
  console.log('usage: node bin/quant.mjs <backtest|paper> [--days N] [--out DIR]');
  process.exit(2);
}
