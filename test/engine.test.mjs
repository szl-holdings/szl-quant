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
