import test from 'node:test';
import assert from 'node:assert/strict';
import { canonicalize } from '../src/canonical-json.mjs';
import { signEnvelope, verifyEnvelope, pae } from '../src/dsse.mjs';
import { generateEngineKeypair } from '../src/keys.mjs';
import { capTrust, TRUST_CEILING, labeled, unavailable, LABELS } from '../src/canon.mjs';
import { lambdaAggregate, lambdaBounded, hoeffdingConfidence, zScore, periodReturn } from '../src/formulas.mjs';
import { freshnessGate, sampleSizeGate, liquidityGate, volatilityGate, convictionGate, loopTaxGate, postureGate, runGates } from '../src/gates.mjs';
import { makeLoopTaxLedger, chargeLoopTax, runBoundedLoop } from '../src/ouroboros.mjs';
import { makeBook, paperFill, markToMarket, toMicroUsd, microToUsdString } from '../src/portfolio.mjs';
import { replaySeries } from '../src/backtest.mjs';
import { signReceipt, PREDICATE } from '../src/receipts.mjs';

test('canonical JSON sorts keys recursively and rejects non-finite', () => {
  assert.equal(canonicalize({ b: 1, a: { d: 2, c: [3, { z: 1, y: 2 }] } }), '{"a":{"c":[3,{"y":2,"z":1}],"d":2},"b":1}');
  assert.throws(() => canonicalize({ x: Infinity }));
});

test('DSSE roundtrip verifies; tampered payload fails closed', () => {
  const { privateKey, publicKey } = generateEngineKeypair();
  const env = signEnvelope({ hello: 'world', n: 1 }, privateKey, publicKey);
  assert.equal(verifyEnvelope(env, publicKey).ok, true);
  const tampered = { ...env, payload: Buffer.from('{"hello":"worId","n":1}').toString('base64') };
  assert.equal(verifyEnvelope(tampered, publicKey).ok, false);
  const noKey = { ...env };
  delete noKey.publicKeySpkiBase64;
  assert.equal(verifyEnvelope(noKey, null).ok, false); // no key ⇒ fail closed
});

test('PAE is spec-exact', () => {
  const p = pae('t', Buffer.from('ab'));
  assert.equal(p.toString('utf8'), 'DSSEv1 1 t 2 ab');
});

test('trust ceiling caps at 0.97, never 1.0', () => {
  assert.equal(capTrust(1.0), TRUST_CEILING);
  assert.equal(capTrust(0.5), 0.5);
  assert.equal(capTrust(NaN), null);
  assert.equal(TRUST_CEILING, 0.97);
});

test('labels: UNAVAILABLE carries no value; labeled requires value', () => {
  assert.deepEqual(unavailable('feed down'), { label: 'UNAVAILABLE', note: 'feed down' });
  assert.throws(() => labeled(null, LABELS.LIVE));
  assert.throws(() => labeled(1, 'PROVEN'));
});

test('lambdaAggregate: geometric mean, zero-dominant, honest null', () => {
  assert.ok(Math.abs(lambdaAggregate([0.9, 0.9, 0.9]) - 0.9) < 1e-12);
  assert.equal(lambdaAggregate([0.9, 0]), 0);
  assert.equal(lambdaAggregate([]), null);
  assert.equal(lambdaAggregate([1.2]), null); // out of bounds ⇒ no value
  assert.ok(lambdaBounded(0.5) && !lambdaBounded(1.5));
});

test('hoeffding confidence is capped and null on bad input', () => {
  const c = hoeffdingConfidence(100000, 0.05, -0.5, 0.5);
  assert.ok(c !== null && c <= TRUST_CEILING);
  assert.equal(hoeffdingConfidence(0, 0.1, -1, 1), null);
});

test('gates fail closed on missing inputs and block honestly', () => {
  assert.equal(freshnessGate(undefined, Date.now(), 1000).verdict, 'BLOCKED');
  assert.equal(sampleSizeGate(NaN, 10).verdict, 'BLOCKED');
  assert.equal(liquidityGate(null, 5, 1, 1).verdict, 'BLOCKED');
  assert.equal(volatilityGate(undefined, 2).verdict, 'BLOCKED');
  assert.equal(convictionGate(0.99, 0.5).verdict, 'BLOCKED'); // above ceiling ⇒ BLOCKED
  assert.equal(loopTaxGate(null).verdict, 'BLOCKED');
  assert.equal(postureGate().verdict, 'ALLOWED');
  const overall = runGates([postureGate(), volatilityGate(9, 3.5)]);
  assert.equal(overall.verdict, 'BLOCKED');
  assert.deepEqual(overall.blockedBy, ['volatility']);
  const blockedGate = overall.gates.find((g) => g.verdict === 'BLOCKED');
  assert.ok(blockedGate.reason.length > 5); // honest reason present
});

test('loop tax: budget exhausts and gate blocks', () => {
  const ledger = makeLoopTaxLedger({ budget: 2, taxPerStep: 1 });
  chargeLoopTax(ledger, 'a');
  assert.equal(loopTaxGate(ledger).verdict, 'ALLOWED');
  chargeLoopTax(ledger, 'b');
  assert.equal(ledger.remaining, 0);
  assert.equal(loopTaxGate(ledger).verdict, 'BLOCKED');
});

test('bounded loop terminates on budget with honest exitReason', () => {
  const { trace, ledger } = runBoundedLoop({
    initialState: { x: 0 },
    step: (s) => ({ state: { x: s.x + 1 } }),
    delta: (a, b) => Math.abs(b.x - a.x),
    config: { maxSteps: 3, label: 't' },
  });
  assert.equal(trace.exitReason, 'budgetExhausted');
  assert.equal(trace.stepsRun, 3);
  assert.equal(ledger.spent, 3);
});

test('paper book is deterministic and refuses leverage/shorting', () => {
  const mk = () => {
    const b = makeBook({ startingCashUsd: 1000, costModel: { feeBps: 30, slippageBps: 20 } });
    paperFill(b, { asset: 'X', side: 'BUY', notionalUsd: 500, price: 2.5, atIso: 't0', reason: 'test' });
    return markToMarket(b, { X: 3.0 }, 't1');
  };
  const a = mk(), b2 = mk();
  assert.deepEqual(a, b2); // identical inputs ⇒ identical books
  const b3 = makeBook({ startingCashUsd: 100, costModel: { feeBps: 30, slippageBps: 20 } });
  assert.throws(() => paperFill(b3, { asset: 'X', side: 'BUY', notionalUsd: 500, price: 1, atIso: 't', reason: 'r' }));
  assert.throws(() => paperFill(b3, { asset: 'X', side: 'SELL', notionalUsd: 5, price: 1, atIso: 't', reason: 'r' }));
  assert.equal(microToUsdString(toMicroUsd(1.5)), '1.500000');
});

test('markToMarket refuses to invent equity when a position is unpriced', () => {
  const b = makeBook({ startingCashUsd: 1000, costModel: { feeBps: 30, slippageBps: 20 } });
  paperFill(b, { asset: 'X', side: 'BUY', notionalUsd: 100, price: 1, atIso: 't', reason: 'r' });
  const m = markToMarket(b, {}, 't1');
  assert.equal(m.equityUsd, null);
  assert.match(m.equityNote, /unpriced/);
  assert.equal(m.positions[0].value.label, 'UNAVAILABLE');
});

test('backtest replay: deterministic, no lookahead, honest small-n note', () => {
  const series = [];
  let p = 100;
  for (let i = 0; i < 120; i++) { p = p * (1 + Math.sin(i / 7) * 0.02); series.push({ tMs: 1700000000000 + i * 86400000, close: p }); }
  const params = { momentumLookback: 14, zWindow: 10, zEntry: 1.0, volWindow: 20, positionFraction: 0.2 };
  const r1 = replaySeries(series, params, { feeBps: 30, slippageBps: 20 });
  const r2 = replaySeries(series, params, { feeBps: 30, slippageBps: 20 });
  assert.deepEqual(r1, r2);
  if (r1.nRoundTrips < 10 && r1.nRoundTrips > 0) assert.match(r1.winRateNote, /weak evidence/);
});

test('signal receipts carry doctrine block and verify end-to-end', () => {
  const { privateKey, publicKey } = generateEngineKeypair();
  const decision = { verdict: 'BLOCKED', gates: [{ gate: 'volatility', verdict: 'BLOCKED', reason: 'vol over cap' }], conviction: 0.6 };
  const { envelope } = signReceipt({
    predicateType: PREDICATE.signal,
    subjectName: 'test/signal',
    subjectBody: decision,
    predicate: { decision },
    privateKey, publicKey,
  });
  const v = verifyEnvelope(envelope, publicKey);
  assert.equal(v.ok, true);
  assert.equal(v.payload.predicate._doctrine.posture.provenTrust, false);
  assert.equal(v.payload.predicate._doctrine.trustCeiling, 0.97);
  assert.equal(v.payload.predicate.decision.verdict, 'BLOCKED'); // BLOCKED stays BLOCKED
});

// ── resilient history ingest (coingecko → coinbase fallback) ───────────────
import { parseCandles } from '../src/ingest/coinbase.mjs';
import { fetchDailyHistoryResilient, COINBASE_PRODUCTS } from '../src/ingest/history.mjs';

test('coinbase parseCandles: closed candles only, ascending, deduped', () => {
  const day = 86400;
  const t0 = 1700000000 - (1700000000 % day); // aligned bucket starts (sec)
  const now = (t0 + 2 * day + 1000) * 1000;   // t0 and t0+1d closed; t0+2d still open
  // Coinbase rows are newest-first: [time, low, high, open, close, volume]
  const rows = [
    [t0 + 2 * day, 1, 2, 1, 3.5, 10],   // still forming → drop
    [t0 + day, 1, 2, 1, 2.5, 10],       // closed, ok
    [t0, 1, 2, 1, 1.5, 10],             // closed, ok
    [t0, 1, 2, 1, 1.5, 10],             // duplicate bucket → dedupe
    [t0 - day, 1, 2, 1, 'nan', 10],     // bad close → drop
  ];
  const s = parseCandles(rows, now);
  assert.deepEqual(s, [{ tMs: t0 * 1000, close: 1.5 }, { tMs: (t0 + day) * 1000, close: 2.5 }]);
  assert.deepEqual(parseCandles(null, now), []);
});

test('resilient history: primary ok → coingecko serves, chain records it', async () => {
  const fake = { ok: true, series: [{ tMs: 1, close: 2 }], dataset: { source: 'coingecko-public' } };
  const r = await fetchDailyHistoryResilient('bitcoin', 30, { primary: async () => fake, secondary: async () => { throw new Error('must not be called'); } });
  assert.equal(r.ok, true);
  assert.equal(r.dataset.source, 'coingecko-public');
  assert.deepEqual(r.dataset.sourceChain, [{ source: 'coingecko-public', outcome: 'ok' }]);
});

test('resilient history: primary 429 → coinbase fallback, honest chain, no stitching', async () => {
  const cgFail = { ok: false, unavailable: { label: 'UNAVAILABLE', note: 'coingecko bitcoin: HTTP 429' } };
  const cb = { ok: true, series: [{ tMs: 1, close: 2 }, { tMs: 2, close: 3 }], dataset: { source: 'coinbase-exchange-public', vsCurrency: 'USD' } };
  const r = await fetchDailyHistoryResilient('bitcoin', 30, { primary: async () => cgFail, secondary: async (product) => { assert.equal(product, 'BTC-USD'); return cb; } });
  assert.equal(r.ok, true);
  assert.equal(r.dataset.source, 'coinbase-exchange-public');
  assert.equal(r.dataset.sourceChain.length, 2);
  assert.equal(r.dataset.sourceChain[0].outcome, 'unavailable');
  assert.match(r.dataset.sourceChain[0].note, /429/);
  assert.equal(r.dataset.sourceChain[1].outcome, 'ok');
});

test('resilient history: both down → UNAVAILABLE with full chain (fail closed)', async () => {
  const fail = (note) => ({ ok: false, unavailable: { label: 'UNAVAILABLE', note } });
  const r = await fetchDailyHistoryResilient('solana', 30, { primary: async () => fail('cg down'), secondary: async () => fail('bn down') });
  assert.equal(r.ok, false);
  assert.equal(r.unavailable.label, 'UNAVAILABLE');
  assert.match(r.unavailable.note, /cg down/);
  assert.match(r.unavailable.note, /bn down/);
  assert.equal(r.unavailable.sourceChain.length, 2);
});

test('resilient history: unmapped asset with primary down → honest UNAVAILABLE, not a guess', async () => {
  const fail = { ok: false, unavailable: { label: 'UNAVAILABLE', note: 'cg down' } };
  const r = await fetchDailyHistoryResilient('some-unmapped-coin', 30, { primary: async () => fail, secondary: async () => { throw new Error('must not be called'); } });
  assert.equal(r.ok, false);
  assert.match(r.unavailable.note, /no Coinbase product mapping/);
  assert.equal(COINBASE_PRODUCTS['some-unmapped-coin'], undefined);
});

// ── verifiable track record ─────────────────────────────────────────────────
import { scoreSignal, buildTrackRecord, verifySignalEnvelopes, signalTimeMs, HORIZONS_DAYS } from '../src/track.mjs';
import { verifyEnvelope as dsseVerifyEnvelope } from '../src/dsse.mjs';

const T0 = Date.parse('2026-01-01T00:00:00.000Z');
const DAY = 86400000;
const sigStatement = (iso, decision) => ({ subject: [{ name: `szl-quant/signal/T/${iso}`, digest: { sha256: 'x' } }], predicate: { decision } });

test('track: signalTimeMs parses decision clock from subject name', () => {
  const st = sigStatement('2026-01-01T00:00:00.000Z', {});
  assert.equal(signalTimeMs(st), T0);
  assert.equal(signalTimeMs({ subject: [{ name: 'szl-quant/signal/T/garbage' }] }), null);
});

test('track: realized horizons are MEASURED from one source series', () => {
  const series = [0, 1, 2, 3, 4, 5, 6, 7, 8].map((i) => ({ tMs: T0 + i * DAY, close: [100, 110, 105, 103, 102, 101, 99, 90, 95][i] }));
  const { outcomes } = scoreSignal({ statement: sigStatement('2026-01-01T00:00:00.000Z', {}), series, source: 'test-src', nowMs: T0 + 30 * DAY, horizons: HORIZONS_DAYS });
  assert.equal(outcomes.h1d.label, 'MEASURED');
  assert.ok(Math.abs(outcomes.h1d.forwardReturn - 0.10) < 1e-12);           // 100 → 110
  assert.equal(outcomes.h1d.source, 'test-src');
  assert.equal(outcomes.h7d.label, 'MEASURED');
  assert.ok(Math.abs(outcomes.h7d.forwardReturn - (-0.10)) < 1e-12);        // 100 → 90
});

test('track: unelapsed horizon is honest UNAVAILABLE pending, never a guess', () => {
  const series = [{ tMs: T0, close: 100 }];
  const { outcomes } = scoreSignal({ statement: sigStatement('2026-01-01T00:00:00.000Z', {}), series, nowMs: T0 + DAY + 3600000, horizons: [7] });
  assert.equal(outcomes.h7d.label, 'UNAVAILABLE');
  assert.match(outcomes.h7d.note, /pending/);
  assert.ok(outcomes.h7d.pendingUntilIso);
});

test('track: elapsed horizon with missing closes is an honest gap, not silence', () => {
  const series = [{ tMs: T0, close: 100 }, { tMs: T0 + DAY, close: 101 }];
  const { outcomes } = scoreSignal({ statement: sigStatement('2026-01-01T00:00:00.000Z', {}), series, nowMs: T0 + 40 * DAY, horizons: [7] });
  assert.equal(outcomes.h7d.label, 'UNAVAILABLE');
  assert.match(outcomes.h7d.note, /history gap/);
});

test('track: tampered receipts are EXCLUDED by name — only verified enter the record', () => {
  const { privateKey, publicKey } = generateEngineKeypair();
  const mk = (name) => signReceipt({ predicateType: PREDICATE.signal, subjectName: name, subjectBody: { v: name }, predicate: { decision: { v: name } }, privateKey, publicKey }).envelope;
  const good = mk('szl-quant/signal/A/2026-01-01T00:00:00.000Z');
  const bad = mk('szl-quant/signal/B/2026-01-01T00:00:00.000Z');
  bad.payload = Buffer.from(Buffer.from(bad.payload, 'base64').toString().replace(/signal\/B/g, 'signal/Z')).toString('base64');
  const { verified, excluded } = verifySignalEnvelopes([{ file: 'a.json', envelope: good }, { file: 'b.json', envelope: bad }, { file: 'c.json', envelope: null }], publicKey, { verifyEnvelope: dsseVerifyEnvelope });
  assert.equal(verified.length, 1);
  assert.equal(excluded.length, 2);
  assert.deepEqual(excluded.map((x) => x.file).sort(), ['b.json', 'c.json']);
});

test('track: full population — BLOCKED counted as no-calls, ALLOWED scored, weak-evidence note in-band', () => {
  const addr = 'AsseT111';
  const allowed = { file: 's1', statement: sigStatement('2026-01-01T00:00:00.000Z', { asset: { symbol: 'T', address: addr }, verdict: 'ALLOWED', proposedAction: 'ENTER_LONG', conviction: 0.5, snapshot: { priceUsd: 1 } }) };
  const blockedSig = { file: 's2', statement: sigStatement('2026-01-01T00:00:00.000Z', { asset: { symbol: 'U', address: 'other' }, verdict: 'BLOCKED', proposedAction: 'ABSTAIN', blockedBy: ['conviction', 'volatility'] }) };
  const histories = { [addr]: { ok: true, series: [{ tMs: T0, close: 100 }, { tMs: T0 + DAY, close: 130 }], dataset: { source: 'test', sha256: 'abc' } } };
  const rep = buildTrackRecord({ verified: [allowed, blockedSig], excluded: [], histories, nowMs: T0 + 3 * DAY, horizons: [1] });
  assert.equal(rep.population.total, 2);
  assert.equal(rep.population.scored, 1);
  assert.equal(rep.population.blocked, 1);
  assert.deepEqual(rep.population.noCallsByGate, [{ gate: 'conviction', count: 1 }, { gate: 'volatility', count: 1 }]);
  const a = rep.aggregates.h1d;
  assert.equal(a.nRealized, 1);
  assert.equal(a.wins, 1);
  assert.equal(a.hitRate, 1);
  assert.match(a.note, /weak evidence/);
  const row = rep.signals.find((r) => r.file === 's1');
  assert.equal(row.seriesSha256, 'abc');
  assert.equal(row.outcomes.h1d.label, 'MEASURED');
  const nc = rep.signals.find((r) => r.file === 's2');
  assert.equal(nc.scored, false);
  assert.match(nc.note, /no-call/);
});

// ── ledger hash chain ───────────────────────────────────────────────────────
import { buildChainBody, scanLedgerForChain, CHAIN_FILE_RE } from '../src/chain.mjs';

test('chain: genesis seals ALL run dirs with prev=null', () => {
  const runDirs = [
    { dir: 'r1', files: [{ name: 'a.json', sha256: 'h1' }] },
    { dir: 'r2', files: [{ name: 'b.json', sha256: 'h2' }, { name: 'c.json', sha256: 'h3' }] },
  ];
  const b = buildChainBody({ runDirs, prevChain: null, coveredDirs: new Set(), nowIso: '2026-07-15T00:00:00.000Z' });
  assert.equal(b.seq, 1);
  assert.equal(b.prev, null);
  assert.deepEqual(b.covers.map((c) => c.dir), ['r1', 'r2']);
  assert.equal(b.coverage.files, 3);
  assert.match(b.note, /GENESIS/);
  assert.match(b.limits, /head truncation/);
});

test('chain: successor seals only unsealed dirs and pins prev by bytes-hash', () => {
  const runDirs = [
    { dir: 'r1', files: [{ name: 'a.json', sha256: 'h1' }] },
    { dir: 'r2', files: [{ name: 'b.json', sha256: 'h2' }] },
    { dir: 'r3', files: [{ name: 'd.json', sha256: 'h4' }] },
  ];
  const prevChain = { runDir: 'r2', file: 'chain_0001.receipt.json', sha256: 'prevsha', seq: 1 };
  const b = buildChainBody({ runDirs, prevChain, coveredDirs: new Set(['r1', 'r2']), nowIso: '2026-07-15T00:00:00.000Z' });
  assert.equal(b.seq, 2);
  assert.deepEqual(b.prev, { runDir: 'r2', file: 'chain_0001.receipt.json', sha256: 'prevsha' });
  assert.deepEqual(b.covers.map((c) => c.dir), ['r3']);
});

test('chain: nothing unsealed → honest null no-op; unreadable prev seq → fail closed', () => {
  const runDirs = [{ dir: 'r1', files: [] }];
  assert.equal(buildChainBody({ runDirs, prevChain: { seq: 1 }, coveredDirs: new Set(['r1']), nowIso: 'x' }), null);
  assert.throws(() => buildChainBody({ runDirs, prevChain: { seq: null }, coveredDirs: new Set(), nowIso: 'x' }), /refusing to fork/);
});

// ── stateful paper book ─────────────────────────────────────────────────────
import { buildBookBody, DEFAULT_BOOK_CONFIG, BOOK_FILE_RE, decisionForBook } from '../src/book.mjs';

const D = (symbol, proposedAction, verdict, priceUsd, file) => ({ file: file ?? `signal_${symbol}_1.receipt.json`, symbol, proposedAction, verdict, priceUsd, observedAtIso: '2026-07-16T00:00:00.000Z' });

test('book: genesis fills ALLOWED ENTER_LONG at entry fraction of equity; BLOCKED holds the book', () => {
  const b = buildBookBody({ prevBook: null, decisions: [D('AAA', 'ENTER_LONG', 'ALLOWED', 2), D('BBB', 'ENTER_LONG', 'BLOCKED', 3)], runDir: 'r2', nowIso: 'T', allRunDirs: ['r1', 'r2'] });
  assert.equal(b.seq, 1);
  assert.equal(b.prev, null);
  assert.deepEqual(b.preBookRunDirs, ['r1']); // pre-book era declared, never backfilled
  assert.equal(b.fills.length, 1);
  assert.equal(b.fills[0].notionalUsd, '1000.000000'); // 10% of 10k starting equity
  assert.equal(b.state.cashMicro, (9000n * 1_000_000n).toString());
  assert.ok(b.noActions.some((n) => n.asset === 'BBB' && /fail closed/.test(n.why)));
  assert.notEqual(b.mark.equityUsd, null);
});

test('book: insufficient cash → honest SKIPPED, never leverage', () => {
  const cfg = { startingCashUsd: 100, entryFractionBps: 10_000, costModel: { feeBps: 30, slippageBps: 20 } };
  const b = buildBookBody({ prevBook: null, decisions: [D('AAA', 'ENTER_LONG', 'ALLOWED', 1), D('BBB', 'ENTER_LONG', 'ALLOWED', 1)], runDir: 'r1', nowIso: 'T', allRunDirs: ['r1'], config: cfg });
  assert.equal(b.fills.length, 1);
  const skipped = b.noActions.find((n) => n.action === 'SKIPPED_INSUFFICIENT_CASH');
  assert.ok(skipped && skipped.asset === 'BBB' && /no leverage/.test(skipped.why));
});

test('book: successor resurrects state, EXIT realizes, prev pinned by bytes-hash', () => {
  const g = buildBookBody({ prevBook: null, decisions: [D('AAA', 'ENTER_LONG', 'ALLOWED', 2)], runDir: 'r1', nowIso: 'T', allRunDirs: ['r1'] });
  const prevBook = { runDir: 'r1', file: 'book_1.receipt.json', sha256: 'sha-prev', body: g };
  const s = buildBookBody({ prevBook, decisions: [D('AAA', 'EXIT_LONG', 'ALLOWED', 4)], runDir: 'r2', nowIso: 'T2', allRunDirs: ['r1', 'r2'] });
  assert.equal(s.seq, 2);
  assert.deepEqual(s.prev, { runDir: 'r1', file: 'book_1.receipt.json', sha256: 'sha-prev' });
  assert.deepEqual(s.skippedRunDirs, []);
  assert.equal(s.fills.length, 1);
  assert.equal(s.fills[0].side, 'SELL');
  assert.deepEqual(s.state.positions, {});
  assert.ok(BigInt(s.state.cashMicro) > 10_000n * 1_000_000n); // price doubled → paper gain net of MODELED costs
  assert.equal(s.mark.equityUsd, s.mark.cashUsd);
});

test('book: no pyramiding; unpriced open position blocks new entries (fail closed)', () => {
  const g = buildBookBody({ prevBook: null, decisions: [D('AAA', 'ENTER_LONG', 'ALLOWED', 2)], runDir: 'r1', nowIso: 'T', allRunDirs: ['r1'] });
  const prevBook = { runDir: 'r1', file: 'book_1.receipt.json', sha256: 'x', body: g };
  const s = buildBookBody({ prevBook, decisions: [D('AAA', 'ENTER_LONG', 'ALLOWED', 2.2), D('BBB', 'ENTER_LONG', 'ALLOWED', 1)], runDir: 'r2', nowIso: 'T2', allRunDirs: ['r1', 'r2'] });
  assert.ok(s.noActions.some((n) => n.asset === 'AAA' && /no pyramiding/.test(n.why)));
  assert.equal(s.fills.length, 1); // BBB enters — AAA is priced by its own decision snapshot
  const s2 = buildBookBody({ prevBook, decisions: [D('BBB', 'ENTER_LONG', 'ALLOWED', 1)], runDir: 'r2', nowIso: 'T2', allRunDirs: ['r1', 'r2'] });
  assert.equal(s2.fills.length, 0); // AAA unpriced today → equity unknowable → no new entries
  assert.ok(s2.noActions.some((n) => n.asset === 'BBB' && /unpriced/.test(n.why)));
  assert.equal(s2.mark.equityUsd, null); // honest empty
  assert.ok(s2.mark.equityNote);
});

test('book: unreadable prev seq → refuses to fork; config inherited with honest note', () => {
  assert.throws(
    () => buildBookBody({ prevBook: { runDir: 'r1', file: 'book_1.receipt.json', sha256: 'x', body: null }, decisions: [], runDir: 'r2', nowIso: 'T', allRunDirs: ['r1', 'r2'] }),
    /refusing to fork/,
  );
  const cfg = { startingCashUsd: 500, entryFractionBps: 2000, costModel: { feeBps: 1, slippageBps: 2 } };
  const g = buildBookBody({ prevBook: null, decisions: [], runDir: 'r1', nowIso: 'T', allRunDirs: ['r1'], config: cfg });
  const s = buildBookBody({ prevBook: { runDir: 'r1', file: 'book_1.receipt.json', sha256: 'x', body: g }, decisions: [], runDir: 'r2', nowIso: 'T', allRunDirs: ['r1', 'r2'] });
  assert.deepEqual(s.config, cfg); // inherited from the chain, NOT engine defaults
  assert.ok(/INHERITED/.test(s.configNote ?? ''));
  assert.notDeepEqual(cfg, DEFAULT_BOOK_CONFIG);
});

test('book: file-name pattern is strict (no spoofing via lookalike names)', () => {
  assert.ok(BOOK_FILE_RE.test('book_1784108626307.receipt.json'));
  assert.ok(!BOOK_FILE_RE.test('book_.receipt.json'));
  assert.ok(!BOOK_FILE_RE.test('xbook_1.receipt.json'));
  assert.ok(!BOOK_FILE_RE.test('book_1.receipt.json.bak'));
});

test('book: decisionForBook extracts exactly the acted-on fields, null on shape miss', () => {
  const st = { predicate: { decision: { asset: { symbol: 'SOL' }, proposedAction: 'HOLD', verdict: 'ALLOWED', snapshot: { priceUsd: 100, observedAtIso: 'T' } } } };
  assert.deepEqual(decisionForBook('f.json', st), { file: 'f.json', symbol: 'SOL', proposedAction: 'HOLD', verdict: 'ALLOWED', priceUsd: 100, observedAtIso: 'T' });
  assert.equal(decisionForBook('f.json', { predicate: {} }), null);
});

// ── refusal record ──────────────────────────────────────────────────────────
import { buildRefusalsBody, decisionForRefusals, REFUSALS_FILE_RE } from '../src/refusals.mjs';

const RD = [
  { file: 'b.json', symbol: 'BBB', verdict: 'BLOCKED', proposedAction: 'ENTER_LONG', conviction: 0.2, blockedBy: ['conviction', 'freshness'] },
  { file: 'a.json', symbol: 'AAA', verdict: 'ALLOWED', proposedAction: 'HOLD', conviction: 0.6, blockedBy: [] },
  { file: 'c.json', symbol: 'CCC', verdict: 'BLOCKED', proposedAction: 'ENTER_LONG', conviction: null, blockedBy: ['conviction'] },
];

test('refusals: census counts verdicts, actions and blocking gates', () => {
  const b = buildRefusalsBody({ decisions: RD, runDir: 'r1', nowIso: 'T' });
  assert.equal(b.totals.decisions, 3);
  assert.equal(b.totals.allowed, 1);
  assert.equal(b.totals.blocked, 2);
  assert.deepEqual(b.totals.refusalsByGate, [{ gate: 'conviction', count: 2 }, { gate: 'freshness', count: 1 }]); // array — counts must never sit under a gate-named key
  assert.deepEqual(b.totals.byAction, { ENTER_LONG: 2, HOLD: 1 });
  assert.deepEqual(b.decisions.map((d) => d.symbol), ['AAA', 'BBB', 'CCC']); // sorted census
  assert.equal(b.labels.counts, 'MEASURED');
});

test('refusals: deterministic — input order does not change canonical bytes', () => {
  const a = buildRefusalsBody({ decisions: RD, runDir: 'r1', nowIso: 'T' });
  const b = buildRefusalsBody({ decisions: [...RD].reverse(), runDir: 'r1', nowIso: 'T' });
  assert.equal(canonicalize(a), canonicalize(b));
});

test('refusals: honest empty census when a run has no decisions', () => {
  const b = buildRefusalsBody({ decisions: [], runDir: 'r1', nowIso: 'T', excludedSignals: { count: 1, files: ['bad.json'] } });
  assert.deepEqual(b.totals, { decisions: 0, allowed: 0, blocked: 0, byAction: {}, refusalsByGate: [] });
  assert.deepEqual(b.inputs.signalFiles, []);
  assert.deepEqual(b.inputs.excludedSignals, { count: 1, files: ['bad.json'] }); // exclusions still confessed
});

test('refusals: extraction takes exactly the counted fields, null on shape miss', () => {
  const st = { predicate: { decision: { asset: { symbol: 'SOL' }, proposedAction: 'ENTER_LONG', verdict: 'BLOCKED', blockedBy: ['freshness', 'conviction'] } } };
  assert.deepEqual(decisionForRefusals('f.json', st), { file: 'f.json', symbol: 'SOL', verdict: 'BLOCKED', proposedAction: 'ENTER_LONG', conviction: null, blockedBy: ['conviction', 'freshness'] });
  assert.equal(decisionForRefusals('f.json', { predicate: {} }), null);
});

test('refusals: file-name pattern is strict (no spoofing via lookalike names)', () => {
  assert.ok(REFUSALS_FILE_RE.test('refusals_1784223547921.receipt.json'));
  assert.ok(!REFUSALS_FILE_RE.test('refusals_.receipt.json'));
  assert.ok(!REFUSALS_FILE_RE.test('xrefusals_1.receipt.json'));
  assert.ok(!REFUSALS_FILE_RE.test('refusals_1.receipt.json.bak'));
});

// ── external witness (rekor anchoring) ─────────────────────────────────────
import { buildRekordProposal, setMessageBytes, extractRekordFields, buildWitnessBody, witnessFileName, WITNESS_FILE_RE } from '../src/witness.mjs';
import { sign as edSign, verify as edVerifyRaw } from 'node:crypto';

test('witness: rekord proposal round-trips a real ed25519 signature over the artifact', () => {
  const kp = generateEngineKeypair();
  const artifact = Buffer.from('{"chain":"head bytes"}');
  const sig = edSign(null, artifact, kp.privateKey);
  const pem = kp.publicKey.export({ type: 'spki', format: 'pem' });
  const p = buildRekordProposal({ artifactBytes: artifact, signatureBase64: sig.toString('base64'), publicKeyPem: pem });
  assert.equal(p.kind, 'rekord');
  assert.equal(p.spec.signature.format, 'x509');
  const back = Buffer.from(p.spec.data.content, 'base64');
  assert.ok(back.equals(artifact));
  assert.ok(edVerifyRaw(null, back, kp.publicKey, Buffer.from(p.spec.signature.content, 'base64')));
});

test('witness: SET message is RFC8785-canonical with exactly the four rekor fields', () => {
  const bytes = setMessageBytes({ entryBodyBase64: 'B', integratedTime: 7, logID: 'L', logIndex: 42 });
  assert.equal(Buffer.from(bytes).toString('utf8'), '{"body":"B","integratedTime":7,"logID":"L","logIndex":42}');
});

test('witness: extractRekordFields reads canonical entries and fails closed on shape miss', () => {
  const entry = { apiVersion: '0.0.1', kind: 'rekord', spec: { data: { hash: { algorithm: 'sha256', value: 'ab'.repeat(32) } }, signature: { format: 'x509', content: 'c2ln', publicKey: { content: 'cGVt' } } } };
  const b64 = Buffer.from(JSON.stringify(entry)).toString('base64');
  assert.deepEqual(extractRekordFields(b64), { dataSha256: 'ab'.repeat(32), signatureBase64: 'c2ln', publicKeyPemBase64: 'cGVt', format: 'x509' });
  assert.equal(extractRekordFields(Buffer.from('{"kind":"hashedrekord"}').toString('base64')), null);
  assert.equal(extractRekordFields(Buffer.from('{"kind":"rekord","spec":{}}').toString('base64')), null);
  assert.equal(extractRekordFields('not-base64-json'), null);
});

test('witness: body is deterministic, REPORTED-labeled and states its limits', () => {
  const args = {
    chain: { seq: 8, runDir: 'r', file: 'chain_0008.receipt.json', sha256: 'aa'.repeat(32) },
    rekor: { server: 'https://rekor.sigstore.dev', uuid: 'u', logIndex: 1, logID: 'l', integratedTime: 2, entryBodyBase64: 'e', signedEntryTimestampBase64: 's' },
    nowIso: 'T',
  };
  const a = buildWitnessBody(args);
  const b = buildWitnessBody(JSON.parse(JSON.stringify(args)));
  assert.equal(canonicalize(a), canonicalize(b));
  assert.equal(a.labels.anchor, 'REPORTED');
  assert.equal(a.limits.length, 3);
  assert.ok(a.limits.some((l) => l.includes('Merkle inclusion proof is not verified offline here')));
  assert.equal(a.kind, 'szl-quant-witness');
});

test('witness: file name is seq-padded and the pattern is strict', () => {
  assert.equal(witnessFileName(9, 123), 'witness_0009_123.receipt.json');
  assert.ok(WITNESS_FILE_RE.test('witness_0009_123.receipt.json'));
  assert.ok(!WITNESS_FILE_RE.test('witness_9_123.receipt.json'));
  assert.ok(!WITNESS_FILE_RE.test('xwitness_0009_123.receipt.json'));
  assert.ok(!WITNESS_FILE_RE.test('witness_0009_123.receipt.json.bak'));
});

test('chain: file-name pattern is strict (no spoofing via lookalike names)', () => {
  assert.ok(CHAIN_FILE_RE.test('chain_0001.receipt.json'));
  assert.ok(!CHAIN_FILE_RE.test('chain_1.receipt.json'));
  assert.ok(!CHAIN_FILE_RE.test('xchain_0001.receipt.json'));
  assert.ok(!CHAIN_FILE_RE.test('chain_0001.receipt.json.bak'));
});

// ── external witness: Merkle inclusion proofs (frontier 7) ─────────────────
import { rfc6962LeafHash, rfc6962NodeHash, rfc6962Root, parseCheckpoint, verifyCheckpoint, verifyInclusionProof, witnessTargets } from '../src/witness.mjs';
import { generateKeyPairSync as genKeys2, sign as rawSign2, createHash as mkHash2 } from 'node:crypto';

// Independent RFC 6962 implementations (recursive MTH + proof builder) so the
// walker is checked against a second derivation, not against itself.
function naiveMTH(leaves) {
  if (leaves.length === 1) return rfc6962LeafHash(leaves[0]);
  let k = 1; while (k * 2 < leaves.length) k *= 2;
  return rfc6962NodeHash(naiveMTH(leaves.slice(0, k)), naiveMTH(leaves.slice(k)));
}
function naiveProof(m, leaves) {
  if (leaves.length === 1) return [];
  let k = 1; while (k * 2 < leaves.length) k *= 2;
  return m < k
    ? [...naiveProof(m, leaves.slice(0, k)), naiveMTH(leaves.slice(k))]
    : [...naiveProof(m - k, leaves.slice(k)), naiveMTH(leaves.slice(0, k))];
}
function makeCheckpoint(rootBuf, treeSize, ecPriv, ecPub, name) {
  const body = name + ' - 42\n' + treeSize + '\n' + rootBuf.toString('base64') + '\n';
  const hint = mkHash2('sha256').update(ecPub.export({ type: 'spki', format: 'der' })).digest().slice(0, 4);
  const sig = rawSign2('sha256', Buffer.from(body, 'utf8'), ecPriv);
  return body + '\n\u2014 ' + name + ' ' + Buffer.concat([hint, sig]).toString('base64') + '\n';
}

test('witness: RFC6962 audit paths verify against an independently built tree, tampering fails', () => {
  for (const n of [1, 2, 3, 5, 7, 8]) {
    const leaves = Array.from({ length: n }, (_, i) => Buffer.from('leaf-' + i));
    const root = naiveMTH(leaves);
    for (let m = 0; m < n; m++) {
      const path = naiveProof(m, leaves).map((b) => b.toString('hex'));
      const got = rfc6962Root({ leafIndex: m, treeSize: n, leafHash: rfc6962LeafHash(leaves[m]), pathHex: path });
      assert.equal(got.toString('hex'), root.toString('hex'), 'size ' + n + ' leaf ' + m);
    }
  }
  const leaves = Array.from({ length: 5 }, (_, i) => Buffer.from('leaf-' + i));
  const path = naiveProof(2, leaves).map((b) => b.toString('hex'));
  const bad = [...path]; bad[0] = bad[0].replace(/^../, bad[0].startsWith('00') ? '11' : '00');
  const got = rfc6962Root({ leafIndex: 2, treeSize: 5, leafHash: rfc6962LeafHash(leaves[2]), pathHex: bad });
  assert.notEqual(got.toString('hex'), naiveMTH(leaves).toString('hex'));
});

test('witness: rfc6962Root fails closed on structural violations', () => {
  const leaf = rfc6962LeafHash(Buffer.from('x'));
  assert.throws(() => rfc6962Root({ leafIndex: 5, treeSize: 5, leafHash: leaf, pathHex: [] }), /outside tree/);
  assert.throws(() => rfc6962Root({ leafIndex: 1, treeSize: 4, leafHash: leaf, pathHex: [] }), /too short/);
  const leaves = [Buffer.from('a'), Buffer.from('b')];
  const path = naiveProof(0, leaves).map((b) => b.toString('hex'));
  assert.throws(() => rfc6962Root({ leafIndex: 0, treeSize: 2, leafHash: rfc6962LeafHash(leaves[0]), pathHex: [...path, path[0]] }), /unconsumed/);
  assert.throws(() => rfc6962Root({ leafIndex: 0, treeSize: 2, leafHash: rfc6962LeafHash(leaves[0]), pathHex: ['abcd'] }), /32 bytes/);
});

test('witness: checkpoint signed-note roundtrip — pinned-hint match, tamper and wrong-key fail', () => {
  const { privateKey: p1, publicKey: k1 } = genKeys2('ec', { namedCurve: 'prime256v1' });
  const { publicKey: k2 } = genKeys2('ec', { namedCurve: 'prime256v1' });
  const root = mkHash2('sha256').update('root').digest();
  const cp = makeCheckpoint(root, 123, p1, k1, 'test.log');
  const parsed = parseCheckpoint(cp);
  assert.equal(parsed.treeSize, 123);
  assert.equal(parsed.rootHashHex, root.toString('hex'));
  const ok = verifyCheckpoint(cp, k1.export({ type: 'spki', format: 'pem' }));
  assert.equal(ok.ok, true);
  assert.equal(ok.treeSize, 123);
  const tampered = cp.replace('\n123\n', '\n124\n');
  const bad = verifyCheckpoint(tampered, k1.export({ type: 'spki', format: 'pem' }));
  assert.equal(bad.ok, false);
  const wrongKey = verifyCheckpoint(cp, k2.export({ type: 'spki', format: 'pem' }));
  assert.equal(wrongKey.ok, false);
  assert.match(wrongKey.reason, /hint/);
});

test('witness: parseCheckpoint refuses malformed notes', () => {
  assert.throws(() => parseCheckpoint('no separator at all\n'), /separator/);
  assert.throws(() => parseCheckpoint('origin - 1\nNaN\nAAAA\n\n\u2014 x AAAAAAAA\n'), /tree-size/);
  assert.throws(() => parseCheckpoint('origin - 1\n5\nnot-base64-32\n\n\u2014 x AAAAAAAA\n'), /root hash/);
  assert.throws(() => parseCheckpoint('origin - 1\n5\n' + Buffer.alloc(32).toString('base64') + '\n\nbad sig line\n'), /signature line/);
});

test('witness: verifyInclusionProof binds the exact entry bytes to the signed root', () => {
  const { privateKey: ecPriv, publicKey: ecPub } = genKeys2('ec', { namedCurve: 'prime256v1' });
  const pem = ecPub.export({ type: 'spki', format: 'pem' });
  const entryBytes = Buffer.from(JSON.stringify({ kind: 'rekord', spec: { data: { hash: { algorithm: 'sha256', value: 'aa' } } } }));
  const leaves = [Buffer.from('other-0'), entryBytes, Buffer.from('other-2'), Buffer.from('other-3')];
  const root = naiveMTH(leaves);
  const proof = {
    logIndex: 1,
    treeSize: 4,
    rootHash: root.toString('hex'),
    hashes: naiveProof(1, leaves).map((b) => b.toString('hex')),
    checkpoint: makeCheckpoint(root, 4, ecPriv, ecPub, 'test.log'),
  };
  const good = verifyInclusionProof({ entryBodyBase64: entryBytes.toString('base64'), proof, logPublicKeyPem: pem });
  assert.equal(good.ok, true);
  const flipped = Buffer.from(entryBytes); flipped[3] ^= 0xff;
  const bad = verifyInclusionProof({ entryBodyBase64: flipped.toString('base64'), proof, logPublicKeyPem: pem });
  assert.equal(bad.ok, false);
  assert.match(bad.reason, /NOT land/);
  const badRoot = { ...proof, rootHash: proof.rootHash.replace(/^../, proof.rootHash.startsWith('00') ? '11' : '00') };
  const rootMismatch = verifyInclusionProof({ entryBodyBase64: entryBytes.toString('base64'), proof: badRoot, logPublicKeyPem: pem });
  assert.equal(rootMismatch.ok, false);
  assert.match(rootMismatch.reason, /root hash mismatch|checkpoint root/i);
});

test('witness: body carries the inclusion proof and states the matching limit', () => {
  const chain = { seq: 3, runDir: 'd', file: 'chain_0003.receipt.json', sha256: 'ab' };
  const rekor = { server: 'https://rekor.sigstore.dev', uuid: 'u', logIndex: 10, logID: 'lid', integratedTime: 1000, entryBodyBase64: 'AA==', signedEntryTimestampBase64: 'BB==' };
  const inclusion = { logIndex: 5, treeSize: 9, rootHash: 'cc', hashes: ['dd'], checkpoint: 'x - 1\n9\nAAA=\n\n\u2014 x AAAAAAAA\n' };
  const withProof = buildWitnessBody({ chain, rekor, inclusion, nowIso: 't' });
  assert.deepEqual(withProof, buildWitnessBody({ chain, rekor, inclusion, nowIso: 't' }));
  assert.equal(withProof.rekor.inclusionProof.treeSize, 9);
  assert.equal(withProof.rekor.inclusionProof.logIndex, 5);
  assert.ok(withProof.limits.some((l) => l.includes('checkpoint captured at anchor time')));
  assert.ok(!withProof.limits.some((l) => l.includes('not verified offline here')));
  const setOnly = buildWitnessBody({ chain, rekor, nowIso: 't' });
  assert.equal(setOnly.rekor.inclusionProof, undefined);
  assert.ok(setOnly.limits.some((l) => l.includes('not verified offline here')));
  assert.ok(withProof.limits.some((l) => l.includes('backfilled')));
});

test('witness: witnessTargets — default anchors the fresh head only, --all backfills unproven links', () => {
  const links = [{ seq: 1 }, { seq: 2 }, { seq: 3 }];
  assert.deepEqual(witnessTargets({ chainLinks: links, receipts: [], all: false }).map((l) => l.seq), [3]);
  assert.deepEqual(witnessTargets({ chainLinks: links, receipts: [{ seq: 3, hasInclusionProof: false }], all: false }), []);
  assert.deepEqual(witnessTargets({ chainLinks: links, receipts: [{ seq: 3, hasInclusionProof: false }], all: true }).map((l) => l.seq), [1, 2, 3]);
  assert.deepEqual(witnessTargets({ chainLinks: links, receipts: [{ seq: 2, hasInclusionProof: true }, { seq: 3, hasInclusionProof: true }], all: true }).map((l) => l.seq), [1]);
  assert.deepEqual(witnessTargets({ chainLinks: [], receipts: [], all: true }), []);
});
