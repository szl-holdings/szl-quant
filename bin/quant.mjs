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
import { buildRekordProposal, buildWitnessBody, witnessFileName, WITNESS_FILE_RE, REKOR_SERVER } from '../src/witness.mjs';
import { sign as rawEdSign } from 'node:crypto';
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
  const keys = ensureIdentity(KEY_PRIV, KEY_PUB_JSON);
  const { chains } = scanLedgerForChain(ledgerDir, { readdirSync, readFileSync });
  const head = chains.length ? chains[chains.length - 1] : null;
  if (!head || !Number.isInteger(head.seq)) { console.log('witness: no chain head to anchor — nothing to witness'); return; }
  ensureDirSync(witnessDir, { recursive: true });
  const prefix = 'witness_' + String(head.seq).padStart(4, '0') + '_';
  if (readdirSync(witnessDir).some((n) => WITNESS_FILE_RE.test(n) && n.startsWith(prefix))) {
    console.log(`witness: chain head seq ${head.seq} already anchored — honest no-op`);
    return;
  }
  const chainBytes = readFileSync(join(ledgerDir, head.runDir, head.file));
  const sig = rawEdSign(null, chainBytes, keys.privateKey);
  const pem = keys.publicKey.export({ type: 'spki', format: 'pem' });
  const proposal = buildRekordProposal({ artifactBytes: chainBytes, signatureBase64: sig.toString('base64'), publicKeyPem: pem });
  // Fail-soft on ANY rekor problem: an unwitnessed head is an honest,
  // counted gap — inventing or deferring receipts would not be.
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
      // identical entry already integrated (e.g. rerun) — fetch it; same anchor
      const loc = res.headers.get('location');
      if (loc) {
        const res2 = await fetch(`${REKOR_SERVER}${loc}`, { headers: { Accept: 'application/json' }, signal: AbortSignal.timeout(30000) });
        if (res2.ok) entry = await res2.json();
      }
      if (!entry) { console.log('witness UNAVAILABLE — rekor reports the entry exists (409) but re-fetch failed — no receipt written (absence is honest)'); return; }
    } else {
      console.log(`witness UNAVAILABLE — rekor HTTP ${res.status}: ${(await res.text()).slice(0, 160)} — no receipt written (absence is honest)`);
      return;
    }
  } catch (e) {
    console.log(`witness UNAVAILABLE — rekor unreachable (${e.message}) — no receipt written (absence is honest)`);
    return;
  }
  const uuid = Object.keys(entry ?? {})[0];
  const rec = uuid ? entry[uuid] : null;
  if (!rec?.verification?.signedEntryTimestamp || !rec.body || !Number.isInteger(rec.logIndex) || !Number.isInteger(rec.integratedTime) || !rec.logID) {
    console.log('witness UNAVAILABLE — rekor response missing SET/body/logIndex — no receipt written (absence is honest)');
    return;
  }
  const body = buildWitnessBody({
    chain: { seq: head.seq, runDir: head.runDir, file: head.file, sha256: head.sha256 },
    rekor: { server: REKOR_SERVER, uuid, logIndex: rec.logIndex, logID: rec.logID, integratedTime: rec.integratedTime, entryBodyBase64: rec.body, signedEntryTimestampBase64: rec.verification.signedEntryTimestamp },
    nowIso: new Date().toISOString(),
  });
  const { envelope } = signReceipt({
    predicateType: PREDICATE.witness,
    subjectName: `szl-quant/witness/chain-seq-${head.seq}`,
    subjectBody: body,
    predicate: { summary: body },
    privateKey: keys.privateKey, publicKey: keys.publicKey,
  });
  const file = join(witnessDir, witnessFileName(head.seq, Date.now()));
  writeFileSync(file, JSON.stringify(envelope, null, 2) + '\n');
  console.log(`witness: chain head seq ${head.seq} anchored in rekor — logIndex ${rec.logIndex}, uuid ${uuid.slice(0, 16)}… [REPORTED] → ${file}`);
  console.log('  note: the anchor lives in a public append-only log — deleting the ledger does not delete it');
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
