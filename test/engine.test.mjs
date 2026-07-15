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
