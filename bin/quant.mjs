#!/usr/bin/env node
/**
 * quant.mjs — CLI for the SZL doctrine-governed quant engine.
 *
 *   node bin/quant.mjs backtest [--days 365] [--out receipts/]
 *   node bin/quant.mjs paper    [--out receipts/]
 *   node bin/quant.mjs track    [--ledger ledger/] [--out receipts/] [--histdays 60]
 *   node bin/quant.mjs chain    [--ledger ledger/] [--dest <run-dir>]
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
import { buildRefusalsBody, decisionForRefusals, REFUSALS_FILE_RE } from '../src/refusals.mjs';
import { buildRekordProposal, buildWitnessBody, witnessFileName, witnessTargets, WITNESS_FILE_RE, REKOR_SERVER, buildConsistencyBody, consistencyTargets, consistencyFileName, rfc6962VerifyConsistency, parseCheckpoint, CONSISTENCY_FILE_RE } from '../src/witness.mjs';
import { sign as rawEdSign, createHash, randomBytes } from 'node:crypto';
import { buildTimestampRequest, parseTimestampResponse, verifyTimestampToken, tsaFileName, TSA_FILE_RE, buildTsaBody } from '../src/tsa.mjs';
import { verifyObservation, buildGossipBody, gossipFileName, OBS_FILE_RE, GOSSIP_FILE_RE, GOSSIP_SOURCE } from '../src/gossip.mjs';

const TSA_AUTHORITIES = [
  { name: 'DigiCert', url: 'http://timestamp.digicert.com', anchor: 'digicert_anchor.pem' },
  { name: 'FreeTSA', url: 'https://freetsa.org/tsr', anchor: 'freetsa_anchor.pem' },
];
const TSA_ANCHOR_DIR = join(dirname(fileURLToPath(import.meta.url)), '..', 'keys', 'tsa');
import { mkdirSync as ensureDirSync } from 'node:fs';
import { scanLedgerForChain, buildChainBody } from '../src/chain.mjs';
import { scanLedgerForBook, buildBookBody, decisionForBook } from '../src/book.mjs';
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
  'jtojtomepa8beP8AuQc6eXt5FriJwfFMwQx2v2f9mCL',  // JTO  (coinbase JTO-USD fallback confirmed)
  'HZ1JovNiVvGrGNiiYvEozEVgZ58xaU3RKwX8eACQBCt3', // PYTH (coinbase PYTH-USD fallback confirmed)
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

async function cmdChain() {
  const ledgerDir = arg('ledger', join(ROOT, 'ledger'));
  const destArg = arg('dest', null);
  const keys = ensureIdentity(KEY_PRIV, KEY_PUB_JSON);
  const state = scanLedgerForChain(ledgerDir, { readdirSync, readFileSync });
  if (state.runDirs.length === 0) { console.log(`chain: no run dirs under ${ledgerDir} — nothing to seal`); return; }
  const body = buildChainBody({ runDirs: state.runDirs, prevChain: state.prevChain, coveredDirs: state.coveredDirs, nowIso: new Date().toISOString() });
  if (body === null) { console.log('chain: every run dir already sealed — nothing new (honest no-op)'); return; }
  const destDir = destArg ?? state.runDirs[state.runDirs.length - 1].dir;
  if (!state.runDirs.some((r) => r.dir === destDir)) { console.error(`chain: dest dir ${destDir} not found under ${ledgerDir}`); process.exit(1); }
  const { envelope } = signReceipt({
    predicateType: PREDICATE.chain,
    subjectName: `szl-quant/chain/${String(body.seq).padStart(4, '0')}`,
    subjectBody: body,
    predicate: { summary: body },
    privateKey: keys.privateKey, publicKey: keys.publicKey,
  });
  const file = join(ledgerDir, destDir, `chain_${String(body.seq).padStart(4, '0')}.receipt.json`);
  writeFileSync(file, JSON.stringify(envelope, null, 2) + '\n');
  console.log(`chain: seq ${body.seq}${body.prev ? ` (prev ${body.prev.sha256.slice(0, 12)}…)` : ' (GENESIS — backfilled all prior runs)'} seals ${body.coverage.dirs} dir(s) / ${body.coverage.files} file(s) → ${file}`);
}

async function cmdBook() {
  const ledgerDir = arg('ledger', join(ROOT, 'ledger'));
  const destArg = arg('dest', null);
  const keys = ensureIdentity(KEY_PRIV, KEY_PUB_JSON);
  // Act only on receipts that verify against the PINNED identity.
  const pinned = loadPublicKeyFromSpkiBase64(JSON.parse(readFileSync(KEY_PUB_JSON, 'utf8')).publicKeySpkiBase64);
  const scan = scanLedgerForBook(ledgerDir, { readdirSync, readFileSync });
  if (scan.dirs.length === 0) { console.log(`book: no run dirs under ${ledgerDir} — nothing to account`); return; }
  const destDir = destArg ?? scan.dirs[scan.dirs.length - 1];
  if (!scan.dirs.includes(destDir)) { console.error(`book: dest dir ${destDir} not found under ${ledgerDir}`); process.exit(1); }
  if (scan.books.some((b) => b.runDir === destDir)) { console.log(`book: ${destDir} already has a book receipt — honest no-op`); return; }
  if (scan.prevBook) {
    // Fail closed: never extend a book whose previous state cannot be verified.
    let v;
    try { v = verifyEnvelope(JSON.parse(readFileSync(join(ledgerDir, scan.prevBook.runDir, scan.prevBook.file), 'utf8')), pinned); }
    catch (e) { v = { ok: false, fails: [String(e?.message ?? e)] }; }
    if (!v.ok) { console.error(`book: PREVIOUS book receipt fails verification — refusing to extend a tampered book (fail closed): ${(v.fails ?? []).join('; ')}`); process.exit(1); }
  }
  const names = readdirSync(join(ledgerDir, destDir)).filter((n) => n.startsWith('signal_') && n.endsWith('.receipt.json')).sort();
  const entries = names.map((n) => {
    try { return { file: n, envelope: JSON.parse(readFileSync(join(ledgerDir, destDir, n), 'utf8')) }; }
    catch { return { file: n, envelope: null }; }
  });
  const { verified, excluded } = verifySignalEnvelopes(entries, pinned, { verifyEnvelope });
  for (const x of excluded) console.log(`  EXCLUDED (unverifiable — will NOT move the book): ${x.file}`);
  const decisions = verified.map(({ file, statement }) => decisionForBook(file, statement)).filter(Boolean);
  const body = buildBookBody({
    prevBook: scan.prevBook, decisions, runDir: destDir, nowIso: new Date().toISOString(),
    allRunDirs: scan.dirs, excludedSignals: { count: excluded.length, files: excluded.map((x) => x.file).sort() },
  });
  const { envelope } = signReceipt({
    predicateType: PREDICATE.book,
    subjectName: `szl-quant/book/${String(body.seq).padStart(4, '0')}`,
    subjectBody: body,
    predicate: { summary: body },
    privateKey: keys.privateKey, publicKey: keys.publicKey,
  });
  const file = join(ledgerDir, destDir, `book_${Date.now()}.receipt.json`);
  writeFileSync(file, JSON.stringify(envelope, null, 2) + '\n');
  for (const f of body.fills) console.log(`  FILL ${f.side} ${f.asset} notional=${f.notionalUsd} eff=${f.effectivePrice} [MODELED costs]`);
  for (const n of body.noActions) console.log(`  ${n.asset}: ${n.action} — ${n.why}`);
  console.log(`book: seq ${body.seq}${body.prev ? ` (prev ${body.prev.sha256.slice(0, 12)}…)` : ' (GENESIS — paper fund starts here)'} fills=${body.fills.length} cash=${body.mark.cashUsd} equity=${body.mark.equityUsd ?? 'UNAVAILABLE (honest empty)'} [MODELED] → ${file}`);
}

async function cmdRefusals() {
  const ledgerDir = arg('ledger', join(ROOT, 'ledger'));
  const destArg = arg('dest', null);
  const keys = ensureIdentity(KEY_PRIV, KEY_PUB_JSON);
  // Count only receipts that verify against the PINNED identity.
  const pinned = loadPublicKeyFromSpkiBase64(JSON.parse(readFileSync(KEY_PUB_JSON, 'utf8')).publicKeySpkiBase64);
  let dirs;
  try {
    dirs = readdirSync(ledgerDir, { withFileTypes: true }).filter((e) => e.isDirectory()).map((e) => e.name).sort();
  } catch {
    console.log(`refusals: no ledger at ${ledgerDir} — nothing to count`);
    return;
  }
  if (dirs.length === 0) { console.log(`refusals: no run dirs under ${ledgerDir} — nothing to count`); return; }
  const destDir = destArg ?? dirs[dirs.length - 1];
  if (!dirs.includes(destDir)) { console.error(`refusals: dest dir ${destDir} not found under ${ledgerDir}`); process.exit(1); }
  if (readdirSync(join(ledgerDir, destDir)).some((n) => REFUSALS_FILE_RE.test(n))) {
    console.log(`refusals: ${destDir} already has a refusal record — honest no-op`);
    return;
  }
  const names = readdirSync(join(ledgerDir, destDir)).filter((n) => n.startsWith('signal_') && n.endsWith('.receipt.json')).sort();
  const entries = names.map((n) => {
    try { return { file: n, envelope: JSON.parse(readFileSync(join(ledgerDir, destDir, n), 'utf8')) }; }
    catch { return { file: n, envelope: null }; }
  });
  const { verified, excluded } = verifySignalEnvelopes(entries, pinned, { verifyEnvelope });
  for (const x of excluded) console.log(`  EXCLUDED (unverifiable — will NOT be counted): ${x.file}`);
  const decisions = verified.map(({ file, statement }) => decisionForRefusals(file, statement)).filter(Boolean);
  const body = buildRefusalsBody({
    decisions, runDir: destDir, nowIso: new Date().toISOString(),
    excludedSignals: { count: excluded.length, files: excluded.map((x) => x.file).sort() },
  });
  const { envelope } = signReceipt({
    predicateType: PREDICATE.refusals,
    subjectName: `szl-quant/refusals/${destDir}`,
    subjectBody: body,
    predicate: { summary: body },
    privateKey: keys.privateKey, publicKey: keys.publicKey,
  });
  const file = join(ledgerDir, destDir, `refusals_${Date.now()}.receipt.json`);
  writeFileSync(file, JSON.stringify(envelope, null, 2) + '\n');
  const gates = [...body.totals.refusalsByGate].sort((a, b) => b.count - a.count).map((x) => `${x.gate}\u00d7${x.count}`).join(' ');
  console.log(`refusals: ${destDir} — BLOCKED ${body.totals.blocked}/${body.totals.decisions}${gates ? ` — by gate: ${gates}` : ''} [MEASURED] → ${file}`);
  console.log('  note: a BLOCKED verdict is a decision, not an absence — the reasons are now countable on the ledger');
}

async function cmdWitness() {
  const ledgerDir = arg('ledger', join(ROOT, 'ledger'));
  const witnessDir = arg('witness-dir', join(ROOT, 'witness'));
  const all = process.argv.includes('--all');
  const keys = ensureIdentity(KEY_PRIV, KEY_PUB_JSON);
  const { chains } = scanLedgerForChain(ledgerDir, { readdirSync, readFileSync });
  if (!chains.length || !chains.every((c) => Number.isInteger(c.seq))) { console.log('witness: no chain links to anchor — nothing to witness'); return; }
  ensureDirSync(witnessDir, { recursive: true });
  const receipts = [];
  for (const n of readdirSync(witnessDir)) {
    if (!WITNESS_FILE_RE.test(n)) continue;
    try {
      const b = JSON.parse(Buffer.from(JSON.parse(readFileSync(join(witnessDir, n), 'utf8')).payload, 'base64').toString('utf8')).predicate.summary;
      receipts.push({ seq: b.chain.seq, hasInclusionProof: Boolean(b.rekor?.inclusionProof) });
    } catch { /* unreadable receipts fail loudly in verify, not here */ }
  }
  const targets = witnessTargets({ chainLinks: chains, receipts, all });
  if (!targets.length) {
    console.log(all
      ? 'witness: every chain link already carries a proof-bearing anchor — honest no-op'
      : `witness: chain head seq ${chains[chains.length - 1].seq} already anchored — honest no-op`);
  } else {
    let anchored = 0;
    let gaps = 0;
    for (const link of targets) {
      const ok = await anchorOneLink({ link, ledgerDir, witnessDir, keys });
      if (ok) anchored += 1; else gaps += 1;
    }
    if (targets.length > 1 || gaps > 0) {
      console.log(`witness: anchored ${anchored}/${targets.length} link(s)` + (gaps > 0 ? ` — ${gaps} gap(s) stay counted in the open (rekor trouble); absence is honest` : ''));
    }
  }
  await consistencyPass({ witnessDir, keys });
  await tsaPass({ witnessDir, keys, all: all });
  await gossipPass({ witnessDir, ledgerDir, keys });
}

/** Generation 3: link every adjacent pair of captured checkpoints with an
 *  RFC 6962 consistency proof — proven append-only growth, single
 *  observer, no gossip pretense. Fail-soft per edge: a missing proof is
 *  an honest counted gap, never an invented receipt. */
async function consistencyPass({ witnessDir, keys }) {
  const checkpoints = [];
  const covered = [];
  for (const n of readdirSync(witnessDir)) {
    try {
      if (WITNESS_FILE_RE.test(n)) {
        const bytes = readFileSync(join(witnessDir, n));
        const b = JSON.parse(Buffer.from(JSON.parse(bytes.toString('utf8')).payload, 'base64').toString('utf8')).predicate.summary;
        const ip = b.rekor?.inclusionProof;
        if (!ip) continue; // generation-1 SET-only receipt: no checkpoint to link
        const cp = parseCheckpoint(ip.checkpoint);
        checkpoints.push({ origin: cp.origin, treeSize: ip.treeSize, rootHash: ip.rootHash, receiptFile: n, receiptSha256: createHash('sha256').update(bytes).digest('hex') });
      } else if (CONSISTENCY_FILE_RE.test(n)) {
        const b = JSON.parse(Buffer.from(JSON.parse(readFileSync(join(witnessDir, n), 'utf8')).payload, 'base64').toString('utf8')).predicate.summary;
        covered.push({ origin: b.origin, prevTreeSize: b.prev.treeSize, nextTreeSize: b.next.treeSize });
      }
    } catch { /* unreadable receipts fail loudly in verify, not here */ }
  }
  const targets = consistencyTargets({ checkpoints, covered });
  if (!targets.length) {
    if (checkpoints.length > 1) console.log('witness: checkpoint consistency chain already complete — honest no-op');
    return;
  }
  let written = 0;
  let gaps = 0;
  for (const t of targets) {
    const ok = await proveOneEdge({ t, witnessDir, keys });
    if (ok) written += 1; else gaps += 1;
  }
  console.log(`witness: consistency edges proven ${written}/${targets.length}` + (gaps > 0 ? ` — ${gaps} unproven edge(s) stay counted in the open; absence is honest` : ' — every adjacent checkpoint pair is linked'));
}

/** Prove ONE adjacent checkpoint pair append-only. The proof is replayed
 *  locally BEFORE signing — this engine never receipts a claim it has not
 *  itself verified offline. */
async function proveOneEdge({ t, witnessDir, keys }) {
  const treeID = t.origin.split(' - ')[1];
  let hashes = null;
  try {
    const url = `${REKOR_SERVER}/api/v1/log/proof?firstSize=${t.prev.treeSize}&lastSize=${t.next.treeSize}&treeID=${treeID}`;
    const res = await fetch(url, { headers: { Accept: 'application/json' }, signal: AbortSignal.timeout(30000) });
    if (!res.ok) {
      console.log(`witness UNAVAILABLE (consistency ${t.prev.treeSize} -> ${t.next.treeSize}) — rekor HTTP ${res.status} — no receipt written (absence is honest)`);
      return false;
    }
    const p = await res.json();
    if (!Array.isArray(p.hashes)) throw new Error('response missing hashes');
    // NOTE: the response's rootHash field reflects proof-GENERATION time,
    // not lastSize (verified empirically) — it is deliberately ignored.
    // The only check that matters is the offline replay below, against
    // the two roots this engine holds in SIGNED checkpoints.
    hashes = p.hashes;
  } catch (e) {
    console.log(`witness UNAVAILABLE (consistency ${t.prev.treeSize} -> ${t.next.treeSize}) — rekor unreachable (${e.message}) — no receipt written (absence is honest)`);
    return false;
  }
  try {
    rfc6962VerifyConsistency({ firstSize: t.prev.treeSize, secondSize: t.next.treeSize, firstRootHex: t.prev.rootHash, secondRootHex: t.next.rootHash, proofHex: hashes });
  } catch (e) {
    console.log(`witness UNAVAILABLE (consistency ${t.prev.treeSize} -> ${t.next.treeSize}) — fetched proof does NOT verify (${e.message}) — no receipt written`);
    return false;
  }
  const body = buildConsistencyBody({ origin: t.origin, prev: t.prev, next: t.next, proofHashes: hashes, nowIso: new Date().toISOString() });
  const { envelope } = signReceipt({
    predicateType: PREDICATE.witness,
    subjectName: `szl-quant/witness/consistency-${t.prev.treeSize}-${t.next.treeSize}`,
    subjectBody: body,
    predicate: { summary: body },
    privateKey: keys.privateKey, publicKey: keys.publicKey,
  });
  const file = join(witnessDir, consistencyFileName(t.prev.treeSize, t.next.treeSize, Date.now()));
  writeFileSync(file, JSON.stringify(envelope, null, 2) + '\n');
  console.log(`witness: log consistency PROVEN ${t.prev.treeSize} -> ${t.next.treeSize} (${hashes.length} proof hashes, replayed offline before signing) [REPORTED] → ${file}`);
  return true;
}

/** Anchor ONE chain link in Rekor. Fail-soft: any Rekor problem is an
 *  honest, counted gap — inventing or deferring receipts would not be. */
async function anchorOneLink({ link, ledgerDir, witnessDir, keys }) {
  const chainBytes = readFileSync(join(ledgerDir, link.runDir, link.file));
  const sig = rawEdSign(null, chainBytes, keys.privateKey);
  const pem = keys.publicKey.export({ type: 'spki', format: 'pem' });
  const proposal = buildRekordProposal({ artifactBytes: chainBytes, signatureBase64: sig.toString('base64'), publicKeyPem: pem });
  let entry = null;
  try {
    const res = await fetch(`${REKOR_SERVER}/api/v1/log/entries`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
      body: JSON.stringify(proposal),
      signal: AbortSignal.timeout(30000),
    });
    if (res.status === 201) {
      entry = await res.json();
    } else if (res.status === 409) {
      // identical entry already integrated (e.g. rerun or proof upgrade) — fetch it; same anchor
      const loc = res.headers.get('location');
      if (loc) {
        const res2 = await fetch(`${REKOR_SERVER}${loc}`, { headers: { Accept: 'application/json' }, signal: AbortSignal.timeout(30000) });
        if (res2.ok) entry = await res2.json();
      }
      if (!entry) { console.log(`witness UNAVAILABLE (seq ${link.seq}) — rekor reports the entry exists (409) but re-fetch failed — no receipt written (absence is honest)`); return false; }
    } else {
      console.log(`witness UNAVAILABLE (seq ${link.seq}) — rekor HTTP ${res.status}: ${(await res.text()).slice(0, 160)} — no receipt written (absence is honest)`);
      return false;
    }
  } catch (e) {
    console.log(`witness UNAVAILABLE (seq ${link.seq}) — rekor unreachable (${e.message}) — no receipt written (absence is honest)`);
    return false;
  }
  let uuid = Object.keys(entry ?? {})[0];
  let rec = uuid ? entry[uuid] : null;
  if (!rec?.verification?.signedEntryTimestamp || !rec.body || !Number.isInteger(rec.logIndex) || !Number.isInteger(rec.integratedTime) || !rec.logID) {
    console.log(`witness UNAVAILABLE (seq ${link.seq}) — rekor response missing SET/body/logIndex — no receipt written (absence is honest)`);
    return false;
  }
  // Inclusion proof: usually in the same response; if absent, ONE re-fetch —
  // then the receipt states plainly whichever generation it is.
  if (!rec.verification.inclusionProof && uuid) {
    try {
      const res3 = await fetch(`${REKOR_SERVER}/api/v1/log/entries/${uuid}`, { headers: { Accept: 'application/json' }, signal: AbortSignal.timeout(30000) });
      if (res3.ok) {
        const again = await res3.json();
        const u2 = Object.keys(again ?? {})[0];
        if (u2 && again[u2]?.verification?.inclusionProof && again[u2]?.verification?.signedEntryTimestamp) { uuid = u2; rec = again[u2]; }
      }
    } catch { /* proof stays absent — receipt says so honestly */ }
  }
  const ip = rec.verification.inclusionProof;
  const inclusion = ip && Number.isInteger(ip.logIndex) && Number.isInteger(ip.treeSize) && Array.isArray(ip.hashes) && typeof ip.rootHash === 'string' && typeof ip.checkpoint === 'string'
    ? { logIndex: ip.logIndex, treeSize: ip.treeSize, rootHash: ip.rootHash, hashes: ip.hashes, checkpoint: ip.checkpoint }
    : null;
  const body = buildWitnessBody({
    chain: { seq: link.seq, runDir: link.runDir, file: link.file, sha256: link.sha256 },
    rekor: { server: REKOR_SERVER, uuid, logIndex: rec.logIndex, logID: rec.logID, integratedTime: rec.integratedTime, entryBodyBase64: rec.body, signedEntryTimestampBase64: rec.verification.signedEntryTimestamp },
    inclusion,
    nowIso: new Date().toISOString(),
  });
  const { envelope } = signReceipt({
    predicateType: PREDICATE.witness,
    subjectName: `szl-quant/witness/chain-seq-${link.seq}`,
    subjectBody: body,
    predicate: { summary: body },
    privateKey: keys.privateKey, publicKey: keys.publicKey,
  });
  const file = join(witnessDir, witnessFileName(link.seq, Date.now()));
  writeFileSync(file, JSON.stringify(envelope, null, 2) + '\n');
  const proofNote = inclusion ? `Merkle inclusion proof captured (tree size ${ip.treeSize})` : 'SET-only — inclusion proof unavailable, stated in the receipt';
  console.log(`witness: chain link seq ${link.seq} anchored in rekor — logIndex ${rec.logIndex}, uuid ${uuid.slice(0, 16)}… [REPORTED] — ${proofNote} → ${file}`);
  console.log('  note: the anchor lives in a public append-only log — deleting the ledger does not delete it');
  return true;
}

const cmd = process.argv[2];
if (cmd === 'backtest') await cmdBacktest();
else if (cmd === 'paper') await cmdPaper();
else if (cmd === 'track') await cmdTrack();
else if (cmd === 'chain') await cmdChain();
else if (cmd === 'book') await cmdBook();
else if (cmd === 'refusals') await cmdRefusals();
else if (cmd === 'witness') await cmdWitness();
else {
  console.log('usage: node bin/quant.mjs <backtest|paper|track|chain|book|refusals|witness> [--days N] [--out DIR] [--ledger DIR] [--dest RUN_DIR] [--witness-dir DIR]');
  process.exit(2);
}

// ── SECOND WITNESS: RFC 3161 trusted timestamps (frontier 9) ───────────────
// An independent authority with a DIFFERENT root of trust than Rekor
// countersigns the sha256 of each head-anchor witness receipt. Every token
// is verified OFFLINE against the pinned anchors in keys/tsa/ BEFORE the
// engine signs a receipt over it. Authority down = honest counted gap.

async function tsaPass({ witnessDir, keys, all = false }) {
  const bySeq = new Map(); // seq -> newest witness receipt file
  for (const f of readdirSync(witnessDir).sort()) {
    if (!WITNESS_FILE_RE.test(f)) continue;
    bySeq.set(Number(/^witness_(\d{4})_/.exec(f)[1]), f); // RE above has no capture groups
  }
  if (!bySeq.size) return;
  const covered = new Set();
  for (const f of readdirSync(witnessDir)) {
    const m = TSA_FILE_RE.exec(f);
    if (m) covered.add(Number(m[1]));
  }
  const maxSeq = Math.max(...bySeq.keys());
  let targets = [...bySeq.entries()].filter(([seq]) => !covered.has(seq)).map(([seq, f]) => ({ seq, f }));
  if (!all) targets = targets.filter((t) => t.seq === maxSeq);
  if (!targets.length) {
    console.log('witness: every head anchor already carries a second-witness timestamp — honest no-op');
    return;
  }
  let ok = 0;
  for (const t of targets) {
    if (await stampOneHead({ t, witnessDir, keys, backfilled: t.seq !== maxSeq })) ok += 1;
    await sleep(400); // polite pacing to public authorities
  }
  console.log(`witness: second-witness timestamps ${ok}/${targets.length} head anchor(s)${ok === targets.length ? ' — every targeted head is countersigned by an independent authority' : ' — missing tokens are honest gaps, retried next run'}`);
}

async function stampOneHead({ t, witnessDir, keys, backfilled }) {
  const bytes = readFileSync(join(witnessDir, t.f));
  const imprint = createHash('sha256').update(bytes).digest('hex');
  const nonce = randomBytes(8);
  nonce[0] = (nonce[0] & 0x3f) | 0x40; // 0x40..0x7f: positive, minimal DER, nonzero high nibble — byte-stable echo
  for (const a of TSA_AUTHORITIES) {
    let anchorPem;
    try { anchorPem = readFileSync(join(TSA_ANCHOR_DIR, a.anchor), 'utf8'); }
    catch { console.log(`witness UNAVAILABLE (tsa seq ${t.seq}) — no pinned anchor for ${a.name} in keys/tsa/ — refusing to trust an unpinned authority`); continue; }
    let tokenDer;
    try {
      const res = await fetch(a.url, {
        method: 'POST', headers: { 'Content-Type': 'application/timestamp-query' },
        body: buildTimestampRequest(imprint, nonce), signal: AbortSignal.timeout(15000),
      });
      if (!res.ok) { console.log(`witness UNAVAILABLE (tsa seq ${t.seq}) — ${a.name} HTTP ${res.status}`); continue; }
      ({ tokenDer } = parseTimestampResponse(Buffer.from(await res.arrayBuffer())));
    } catch (e) {
      console.log(`witness UNAVAILABLE (tsa seq ${t.seq}) — ${a.name} unreachable/refused (${e.message})`);
      continue;
    }
    let verified;
    try {
      verified = verifyTimestampToken({ tokenDer, expectedImprintHex: imprint, anchors: [anchorPem], expectedNonceHex: nonce.toString('hex'), now: new Date() });
    } catch (e) {
      console.log(`witness UNAVAILABLE (tsa seq ${t.seq}) — ${a.name} token FAILED offline verification (${e.message}) — refusing to receipt an unverifiable token`);
      continue;
    }
    const body = buildTsaBody({
      seq: t.seq, witnessFile: t.f, witnessSha256: imprint,
      authority: { name: a.name, url: a.url }, verified,
      tokenDerBase64: tokenDer.toString('base64'), nonceHex: nonce.toString('hex'),
      backfilled, capturedAt: new Date().toISOString(),
    });
    const { envelope } = signReceipt({
      predicateType: PREDICATE.witness,
      subjectName: `szl-quant/witness/tsa-${t.seq}`,
      subjectBody: body,
      predicate: { summary: body },
      privateKey: keys.privateKey, publicKey: keys.publicKey,
    });
    const file = join(witnessDir, tsaFileName(t.seq, Date.now()));
    writeFileSync(file, JSON.stringify(envelope, null, 2) + '\n');
    console.log(`witness: SECOND WITNESS ${a.name} timestamped seq ${t.seq} genTime=${verified.genTime} (token verified offline against the pinned anchor before signing) [REPORTED] → ${file}`);
    return true;
  }
  console.log(`witness UNAVAILABLE (tsa seq ${t.seq}) — no authority produced a verifiable token — honest gap, retried next run`);
  return false;
}

/** Generation 5: cross-witness gossip — fetch, fully re-verify, and archive
 *  the second observer's signed observations, then account for them in an
 *  engine-signed gossip receipt. Fail-soft: an unreachable observer is an
 *  honest, counted gap; a BAD observation is a loud rejection recorded in
 *  the signed receipt — never a silent drop, never a silent accept. */
async function gossipPass({ witnessDir, ledgerDir, keys }) {
  const gossipDir = join(witnessDir, 'gossip');
  ensureDirSync(gossipDir, { recursive: true });
  let observerPin; let rekorPem;
  try {
    observerPin = JSON.parse(readFileSync(join(ROOT, 'keys', 'observer_pubkey.json'), 'utf8'));
    rekorPem = readFileSync(join(ROOT, 'keys', 'rekor_pubkey.pem'), 'utf8');
  } catch (e) {
    console.log(`gossip UNAVAILABLE — pins missing (${e.message}) — refusing to trust an unpinned observer`);
    return;
  }
  const headers = { Accept: 'application/vnd.github+json', 'User-Agent': 'szl-quant-gossip' };
  const ghTok = process.env.GITHUB_TOKEN ?? process.env.GH_TOKEN;
  if (ghTok) headers.Authorization = `Bearer ${ghTok}`;
  const fetchedAtIso = new Date().toISOString();
  let listing;
  try {
    const res = await fetch(`https://api.github.com/repos/${GOSSIP_SOURCE.repo}/contents/${GOSSIP_SOURCE.dir}?ref=${GOSSIP_SOURCE.branch}`, { headers, signal: AbortSignal.timeout(30000) });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    listing = await res.json();
  } catch (e) {
    console.log(`gossip UNAVAILABLE — cannot list ${GOSSIP_SOURCE.repo}@${GOSSIP_SOURCE.branch} (${e.message}) — no receipt written (absence is honest)`);
    return;
  }
  const remote = (Array.isArray(listing) ? listing : []).filter((x) => OBS_FILE_RE.test(x.name));
  const existing = new Set(readdirSync(gossipDir).filter((n) => OBS_FILE_RE.test(n)));
  const rejected = [];
  let newArchived = 0;
  for (const item of remote.filter((x) => !existing.has(x.name)).sort((p, q) => p.name.localeCompare(q.name))) {
    let bytes;
    try {
      const res = await fetch(item.download_url, { headers: { 'User-Agent': 'szl-quant-gossip' }, signal: AbortSignal.timeout(30000) });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      bytes = Buffer.from(await res.arrayBuffer());
    } catch (e) {
      console.log(`gossip gap — could not fetch ${item.name} (${e.message}); counted in the open, not hidden`);
      continue;
    }
    let outcome;
    try {
      const env = JSON.parse(bytes.toString('utf8'));
      const sm = JSON.parse(Buffer.from(env.payload, 'base64').toString('utf8')).predicate?.summary ?? {};
      let witnessReceiptBytes = null;
      try { witnessReceiptBytes = readFileSync(join(witnessDir, String(sm.ledger?.witnessFile ?? ''))); } catch { /* stays null — fails closed */ }
      let chainSha256Local = null;
      try { chainSha256Local = createHash('sha256').update(readFileSync(join(ledgerDir, String(sm.ledger?.chainRunDir ?? ''), String(sm.ledger?.chainFile ?? '')))).digest('hex'); } catch { /* stays null — fails closed */ }
      outcome = verifyObservation({ envelope: env, observerPubkeyJson: observerPin, rekorPem, witnessReceiptBytes, chainSha256Local });
    } catch (e) {
      outcome = { ok: false, reason: `unparseable observation: ${e.message}` };
    }
    if (outcome.ok) {
      writeFileSync(join(gossipDir, item.name), bytes);
      newArchived += 1;
      console.log(`gossip archived ${item.name} — verdict ${outcome.verdict} (fully re-verified offline before archiving)`);
    } else {
      rejected.push({ file: item.name, reason: outcome.reason });
      console.log(`gossip REJECTED ${item.name}: ${outcome.reason}`);
    }
  }
  const archived = readdirSync(gossipDir).filter((n) => OBS_FILE_RE.test(n)).sort();
  const census = {};
  let newest = null;
  for (const n of archived) {
    try {
      const sm = JSON.parse(Buffer.from(JSON.parse(readFileSync(join(gossipDir, n), 'utf8')).payload, 'base64').toString('utf8')).predicate.summary;
      census[sm.verdict] = (census[sm.verdict] ?? 0) + 1;
      if (!newest || sm.observedAtIso > newest.observedAtIso) newest = { file: n, observedAtIso: sm.observedAtIso, verdict: sm.verdict };
    } catch { /* unreadable archived observation fails loudly in verify */ }
  }
  const haveReceipt = readdirSync(witnessDir).some((n) => GOSSIP_FILE_RE.test(n));
  if (newArchived === 0 && rejected.length === 0 && haveReceipt) {
    console.log(`gossip unchanged — ${archived.length} observation(s) archived, no new receipt written (absence of change is honest)`);
    return;
  }
  const headSeq = Math.max(0, ...readdirSync(witnessDir).map((n) => (WITNESS_FILE_RE.test(n) ? Number(n.slice(8, 12)) : 0)));
  const body = buildGossipBody({ headSeq, fetchedAtIso, remoteTotal: remote.length, newArchived, archivedTotal: archived.length, rejected, census, newestObservation: newest, nowIso: new Date().toISOString() });
  const { envelope } = signReceipt({ predicateType: PREDICATE.gossip, subjectName: `szl-quant/witness/gossip-seq-${headSeq}`, subjectBody: body, predicate: { summary: body }, privateKey: keys.privateKey, publicKey: keys.publicKey });
  writeFileSync(join(witnessDir, gossipFileName(headSeq, Date.now())), JSON.stringify(envelope, null, 2) + '\n');
  console.log(`gossip OK — ${newArchived} new / ${archived.length} total observation(s) from the second observer${rejected.length ? `, ${rejected.length} REJECTED (loud in the receipt)` : ''} → signed gossip receipt [REPORTED]`);
}
