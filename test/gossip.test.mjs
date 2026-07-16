/** Frontier 10 — cross-witness gossip: the second observer's observations
 *  are fully re-verifiable offline, verdicts cannot be editorialized, and
 *  divergent histories are loud. Fixture: a REAL observation produced by
 *  szl-quant-witness (Actions run) over the REAL seq-13 witness receipt. */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { verifyObservation, recomputeVerdict, sweepSplitViews, buildGossipBody, gossipFileName, OBS_FILE_RE, GOSSIP_FILE_RE, GOSSIP_OBSERVATION_PREDICATE } from '../src/gossip.mjs';
import { signEnvelope } from '../src/dsse.mjs';
import { generateEngineKeypair, publicKeySpkiBase64 } from '../src/keys.mjs';
import { canonicalBytes } from '../src/canonical-json.mjs';

const OBS = JSON.parse(readFileSync(new URL('./fixtures/gossip/obs_real.observation.json', import.meta.url), 'utf8'));
const WITNESS_BYTES = readFileSync(new URL('./fixtures/gossip/witness_0013_1784233307672.receipt.json', import.meta.url));
const OBSERVER_PIN = JSON.parse(readFileSync(new URL('../keys/observer_pubkey.json', import.meta.url), 'utf8'));
const ENGINE_PIN = JSON.parse(readFileSync(new URL('../keys/engine_pubkey.json', import.meta.url), 'utf8'));
const REKOR_PEM = readFileSync(new URL('../keys/rekor_pubkey.pem', import.meta.url), 'utf8');
const stOf = (env) => JSON.parse(Buffer.from(env.payload, 'base64').toString('utf8'));
const SUM = stOf(OBS).predicate.summary;
const base = { envelope: OBS, observerPubkeyJson: OBSERVER_PIN, rekorPem: REKOR_PEM, witnessReceiptBytes: WITNESS_BYTES, chainSha256Local: SUM.ledger.chainSha256 };

test('gossip: real observation fully verifies offline', () => {
  const r = verifyObservation(base);
  assert.equal(r.ok, true, r.reason);
  assert.equal(r.verdict, 'PREFIX_OK');
  assert.equal(r.seq, SUM.ledger.headSeq);
  assert.ok(r.liveCp.treeSize >= SUM.engineCheckpoint.treeSize);
});

test('gossip: tampered payload fails DSSE', () => {
  const st = stOf(OBS);
  st.predicate.summary.note = 'tampered';
  const env = { ...OBS, payload: Buffer.from(JSON.stringify(st)).toString('base64') };
  const r = verifyObservation({ ...base, envelope: env });
  assert.equal(r.ok, false);
  assert.match(r.reason, /DSSE/);
});

test('gossip: wrong observer pin is refused', () => {
  const r = verifyObservation({ ...base, observerPubkeyJson: ENGINE_PIN });
  assert.equal(r.ok, false);
});

// Re-sign mutated payloads with a TEST key to exercise the semantic checks
// past DSSE (mirrors the TSA tamper-drill pattern).
const kp = generateEngineKeypair();
const TEST_PIN = { kind: 'szl-quant-observer-pubkey', v: 1, alg: 'ed25519', keyId: kp.keyId, publicKeySpkiBase64: publicKeySpkiBase64(kp.publicKey) };
function resigned(mutate) {
  const st = stOf(OBS);
  st.predicate.summary.observer.keyId = kp.keyId;
  mutate(st);
  return { envelope: signEnvelope(st, kp.privateKey, kp.publicKey), pin: TEST_PIN };
}

test('gossip: tampered live checkpoint note fails offline replay', () => {
  const { envelope, pin } = resigned((st) => {
    const lc = st.predicate.summary.liveCheckpoint;
    lc.rawNote = lc.rawNote.replace(String(lc.treeSize), String(lc.treeSize + 1));
    lc.treeSize = lc.treeSize + 1;
  });
  const r = verifyObservation({ ...base, envelope, observerPubkeyJson: pin });
  assert.equal(r.ok, false);
});

test('gossip: tampered consistency proof cannot keep a rosy verdict', () => {
  const { envelope, pin } = resigned((st) => {
    const p = st.predicate.summary.consistency.proofHashes;
    p[0] = (p[0].startsWith('00') ? '11' : '00') + p[0].slice(2);
  });
  const r = verifyObservation({ ...base, envelope, observerPubkeyJson: pin });
  assert.equal(r.ok, false);
  assert.match(r.reason, /recomputation|verdict/);
});

test('gossip: witness receipt byte mismatch = divergent-history evidence', () => {
  const r = verifyObservation({ ...base, witnessReceiptBytes: Buffer.concat([WITNESS_BYTES, Buffer.from(' ')]) });
  assert.equal(r.ok, false);
  assert.match(r.reason, /DIFFER/);
});

test('gossip: absent witness receipt or chain link fails closed', () => {
  assert.equal(verifyObservation({ ...base, witnessReceiptBytes: null }).ok, false);
  assert.equal(verifyObservation({ ...base, chainSha256Local: null }).ok, false);
  assert.equal(verifyObservation({ ...base, chainSha256Local: 'ab'.repeat(32) }).ok, false);
});

test('gossip: verdict recomputation covers every branch', () => {
  const a = { origin: 'o - 1', treeSize: 5, rootHex: 'aa'.repeat(16) };
  assert.equal(recomputeVerdict({ engineCp: a, liveCp: { origin: 'p - 2', treeSize: 9, rootHex: 'bb'.repeat(16) } }), 'SHARD_ROTATED');
  assert.equal(recomputeVerdict({ engineCp: a, liveCp: { origin: 'o - 1', treeSize: 4, rootHex: 'bb'.repeat(16) } }), 'LOG_REGRESSED');
  assert.equal(recomputeVerdict({ engineCp: a, liveCp: { origin: 'o - 1', treeSize: 5, rootHex: 'aa'.repeat(16) } }), 'ROOTS_EQUAL');
  assert.equal(recomputeVerdict({ engineCp: a, liveCp: { origin: 'o - 1', treeSize: 5, rootHex: 'bb'.repeat(16) } }), 'SPLIT_VIEW');
  assert.equal(recomputeVerdict({ engineCp: a, liveCp: { origin: 'o - 1', treeSize: 9, rootHex: 'bb'.repeat(16) }, proofHashes: ['cc'.repeat(32)] }), 'SPLIT_VIEW');
});

test('gossip: split-view sweep flags same-size different-root checkpoints', () => {
  const cps = [
    { origin: 'o - 1', treeSize: 10, rootHex: 'aa', source: 'engine' },
    { origin: 'o - 1', treeSize: 10, rootHex: 'aa', source: 'observer' },
    { origin: 'o - 1', treeSize: 11, rootHex: 'bb', source: 'later' },
  ];
  assert.equal(sweepSplitViews(cps).length, 0);
  const bad = sweepSplitViews([...cps, { origin: 'o - 1', treeSize: 10, rootHex: 'cc', source: 'evil' }]);
  assert.equal(bad.length, 1);
  assert.deepEqual(bad[0].sources, ['engine', 'evil']);
});

test('gossip: file naming, predicate, and receipt-body honesty', () => {
  assert.match(gossipFileName(13, 123), GOSSIP_FILE_RE);
  assert.equal(OBS_FILE_RE.test('obs_0013_1784.observation.json'), true);
  assert.equal(OBS_FILE_RE.test('witness_0013_1.receipt.json'), false);
  assert.equal(stOf(OBS).predicateType, GOSSIP_OBSERVATION_PREDICATE);
  const body = buildGossipBody({ headSeq: 13, fetchedAtIso: 'x', remoteTotal: 2, newArchived: 1, archivedTotal: 2, rejected: [{ file: 'f', reason: 'r' }], census: { PREFIX_OK: 2 }, newestObservation: null, nowIso: 'y' });
  assert.equal(body.label, 'REPORTED');
  assert.equal(body.kind, 'szl-quant-gossip-check');
  assert.ok(body.limits.length >= 3);
  assert.equal(body.observations.rejected[0].reason, 'r');
  assert.ok(canonicalBytes(body).length > 0);
});
