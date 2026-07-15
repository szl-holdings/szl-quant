#!/usr/bin/env node
/**
 * quant.mjs — CLI for the SZL doctrine-governed quant engine.
 *
 *   node bin/quant.mjs backtest [--days 365] [--out receipts/]
 *   node bin/quant.mjs paper    [--out receipts/]
 *   node bin/quant.mjs track    [--ledger ledger/] [--out receipts/] [--histdays 60]
 *   node bin/quant.mjs verify   — delegates to verify/verify.mjs
 *
 * Advisory research system. PAPER ONLY. Not financial advice.
 */
import { mkdirSync, writeFileSync, readFileSync, readdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { RATE_DELAY_MS, sleep } from '../src/ingest/coingecko.mjs';
import { fetchDailyHistoryResilient, HISTORY_IDS_BY_ADDRESS } from '../src/ingest/history.mjs';
import { fetchSolanaPairs, deepestPairs } from '../src/ingest/dexscreener.mjs';
import { walkForward } from '../src/backtest.mjs';
import { decideLive, DEFAULT_PARAMS, DEFAULT_LIMITS } from '../src/engine.mjs';
import { makeLoopTaxLedger, runBoundedLoop } from '../src/ouroboros.mjs';
import { signReceipt, PREDICATE } from '../src/receipts.mjs';
import { ensureIdentity, loadPublicKeyFromSpkiBase64 } from '../src/keys.mjs';
import { verifyEnvelope } from '../src/dsse.mjs';
import { verifySignalEnvelopes, buildTrackRecord, HORIZONS_DAYS } from '../src/track.mjs';
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
/** CoinGecko ids for the same assets (single source of truth in ingest/history.mjs). */
const LIVE_HISTORY_IDS = HISTORY_IDS_BY_ADDRESS;

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
    console.log(`\n=== ${symbol} (${coinId}) — fetching ${days}d real history (coingecko public → coinbase fallback, REPORTED feed) ===`);
    const hist = await fetchDailyHistoryResilient(coinId, days);
    if (!hist.ok) {
      console.log(`  ${LABELS.UNAVAILABLE}: ${hist.unavailable.note} — no backtest for ${symbol} (fail closed, nothing invented)`);
      await sleep(RATE_DELAY_MS);
      continue;
    }
    console.log(`  dataset src=${hist.dataset.source} n=${hist.dataset.n} ${hist.dataset.firstIso} → ${hist.dataset.lastIso} sha256=${hist.dataset.sha256.slice(0, 16)}…`);
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
    histByAddr[p.baseAddress] = await fetchDailyHistoryResilient(id, 120);
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
    feed: 'dexscreener [REPORTED] + coingecko→coinbase daily history [REPORTED]',
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

async function cmdTrack() {
  const ledgerDir = arg('ledger', join(ROOT, 'ledger'));
  const outDir = arg('out', join(ROOT, 'receipts'));
  const histDays = Number(arg('histdays', '60'));
  mkdirSync(outDir, { recursive: true });
  const keys = ensureIdentity(KEY_PRIV, KEY_PUB_JSON);
  // Score against the PINNED identity — same trust root third parties use.
  const pinned = loadPublicKeyFromSpkiBase64(JSON.parse(readFileSync(KEY_PUB_JSON, 'utf8')).publicKeySpkiBase64);

  const files = [];
  (function walk(d) {
    let ents;
    try { ents = readdirSync(d, { withFileTypes: true }); } catch { return; }
    for (const e of ents) {
      const p = join(d, e.name);
      if (e.isDirectory()) walk(p);
      else if (e.isFile() && e.name.startsWith('signal_') && e.name.endsWith('.receipt.json')) files.push(p);
    }
  })(ledgerDir);
  console.log(`track: ${files.length} signal receipt(s) under ${ledgerDir}`);

  const entries = [];
  for (const file of files) {
    const rel = file.startsWith(ledgerDir) ? file.slice(ledgerDir.length + 1) : file;
    try { entries.push({ file: rel, envelope: JSON.parse(readFileSync(file, 'utf8')) }); }
    catch (e) { entries.push({ file: rel, envelope: null }); }
  }
  const { verified, excluded } = verifySignalEnvelopes(entries, pinned, { verifyEnvelope });
  for (const x of excluded) console.log(`  EXCLUDED (unverifiable): ${x.file} — ${(x.fails ?? []).join('; ')}`);

  // History per unique asset, via the resilient chain (REPORTED, rate-honest).
  const addrs = [...new Set(verified.map((v) => v.statement?.predicate?.decision?.asset?.address).filter(Boolean))];
  const histories = {};
  for (const a of addrs) {
    const id = HISTORY_IDS_BY_ADDRESS[a];
    if (!id) { histories[a] = { ok: false, unavailable: { label: 'UNAVAILABLE', note: 'no history mapping for asset' } }; continue; }
    histories[a] = await fetchDailyHistoryResilient(id, histDays);
    await sleep(RATE_DELAY_MS);
  }

  const nowMs = Date.now();
  const report = buildTrackRecord({ verified, excluded, histories, nowMs, horizons: HORIZONS_DAYS });
  for (const h of HORIZONS_DAYS) {
    const a = report.aggregates[`h${h}d`];
    console.log(`  +${h}d: realized n=${a.nRealized} pending=${a.nPending} gaps=${a.nGaps} hitRate=${a.hitRate === null ? 'null (honest — nothing realized)' : Math.round(a.hitRate * 100) + '%'} [${a.label}] — ${a.note}`);
  }
  console.log(`  population: total=${report.population.total} scored=${report.population.scored} no-calls(BLOCKED)=${report.population.blocked}`);

  const { envelope } = signReceipt({
    predicateType: PREDICATE.track,
    subjectName: `szl-quant/track-record/${report.generatedAtIso}`,
    subjectBody: report,
    predicate: { summary: report },
    privateKey: keys.privateKey, publicKey: keys.publicKey,
  });
  const file = join(outDir, `trackrecord_${nowMs}.receipt.json`);
  writeFileSync(file, JSON.stringify(envelope, null, 2) + '\n');
  console.log(`  signed track-record receipt → ${file}`);
}

const cmd = process.argv[2];
if (cmd === 'backtest') await cmdBacktest();
else if (cmd === 'paper') await cmdPaper();
else if (cmd === 'track') await cmdTrack();
else {
  console.log('usage: node bin/quant.mjs <backtest|paper|track> [--days N] [--out DIR] [--ledger DIR]');
  process.exit(2);
}
