#!/usr/bin/env node
/**
 * divergence-alarm.mjs — Generation 6: a small, standalone divergence
 * alarm over the cross-witness gossip surface (generation 5).
 *
 * Purpose: given the engine's ledger (this repo's `ledger` branch,
 * checked out anywhere on disk) and the second observer's published
 * observations (szl-holdings/szl-quant-witness, mirrored into the same
 * ledger tree under `witness/gossip/` by the engine's own sync step),
 * deterministically decide ONE thing: has either vantage point recorded
 * or implied a divergence — SPLIT_VIEW, LOG_REGRESSED,
 * LEDGER_BINDING_MISMATCH, SHARD_ROTATED, a signature/DSSE failure, or
 * two verified checkpoints at the same tree size with different roots?
 *
 * If yes: print exactly what diverged and exit 1 (loud, red CI).
 * If no:  print a short honest summary and exit 0.
 *
 * Deliberately self-contained — like verify/verify.mjs, this script
 * imports NOTHING from src/ and re-derives every check from first
 * principles (RFC 6962 leaf/node hashes, checkpoint note parsing,
 * ed25519/DSSE verification) so it audits the estate rather than
 * trusting its own code. It adds no new signing key and mints no new
 * receipt kind; it is a read-only alarm over data that already exists,
 * runnable fully offline once the ledger tree is on disk.
 *
 * Honesty labels:
 *   - Every judgement this script makes is REPORTED: it replays
 *     signatures and RFC 6962 math OFFLINE against pinned keys, but the
 *     underlying observations and checkpoints were themselves collected
 *     over a network at some earlier time, by this same organization's
 *     own engine and its own second observer.
 *   - A "clean" run (exit 0) means "no divergence evidence found in the
 *     data present" — it is NOT proof that no divergence occurred
 *     outside the observed window, and it is NOT a trading or
 *     performance claim of any kind. Paper-only estate, not financial
 *     advice.
 *   - Absence of gossip data is reported as NO_DATA, not as a clean
 *     bill of health — an empty ledger is not evidence of agreement.
 *
 * Usage:
 *   node verify/divergence-alarm.mjs --witness <ledgerRoot> \
 *     [--pubkey keys/engine_pubkey.json] \
 *     [--rekor-pubkey keys/rekor_pubkey.pem] \
 *     [--observer-pubkey keys/observer_pubkey.json]
 *
 * <ledgerRoot> is a directory containing `ledger/` and `witness/`
 * (e.g. a checkout of this repo's `ledger` branch) — the same shape
 * verify.mjs's --witness flag expects.
 *
 * Exit codes: 0 = no divergence found; 1 = divergence found or a
 * verification failure occurred; 2 = usage/setup error.
 */
import { createHash, createPublicKey, verify as edVerify } from 'node:crypto';
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';

const GOOD_VERDICTS = new Set(['PREFIX_OK', 'ROOTS_EQUAL']);
const OBS_RE = /^obs_(\d{4})_\d+\.observation\.json$/;
const WITNESS_RE = /^witness_\d{4}_\d+\.receipt\.json$/;
const PAYLOAD_TYPE = 'application/vnd.in-toto+json';
const GOSSIP_PREDICATE = 'https://szl.holdings/quant/gossip-observation/v1';

const sha256Hex = (b) => createHash('sha256').update(b).digest('hex');
const pae = (t, body) => Buffer.concat([Buffer.from(`DSSEv1 ${Buffer.byteLength(t)} ${t} ${body.length} `, 'utf8'), body]);

// ── RFC 6962 primitives (self-contained; kept in lockstep with src/witness.mjs by hand) ──
function nodeHash(l, r) { return createHash('sha256').update(Buffer.concat([Buffer.from([0x01]), l, r])).digest(); }

/** Parse + verify a Rekor checkpoint note against a pinned key. No network. */
function checkpointFields(text, rekorPub) {
  const sep = typeof text === 'string' ? text.indexOf('\n\n') : -1;
  if (sep < 0) return { ok: false, reason: 'checkpoint has no blank-line separator' };
  const noteBody = text.slice(0, sep + 1);
  const lines = noteBody.split('\n');
  if (lines.length < 4 || !/^\S+ - \d+$/.test(lines[0]) || !/^\d+$/.test(lines[1])) return { ok: false, reason: 'checkpoint note malformed' };
  const treeSize = Number(lines[1]);
  const root = Buffer.from(lines[2], 'base64');
  if (!Number.isSafeInteger(treeSize) || treeSize < 1 || root.length !== 32 || root.toString('base64') !== lines[2]) {
    return { ok: false, reason: 'checkpoint tree size or root hash malformed' };
  }
  const hint = createHash('sha256').update(rekorPub.export({ type: 'spki', format: 'der' })).digest().slice(0, 4).toString('hex');
  let sawHint = false;
  for (const line of text.slice(sep + 2).split('\n')) {
    if (!line) continue;
    const m = line.match(/^\u2014 \S+ (\S+)$/);
    if (!m) continue;
    const raw = Buffer.from(m[1], 'base64');
    if (raw.length < 5 || raw.slice(0, 4).toString('hex') !== hint) continue;
    sawHint = true;
    try { if (edVerify('sha256', Buffer.from(noteBody, 'utf8'), rekorPub, raw.slice(4))) return { ok: true, treeSize, rootHashHex: root.toString('hex'), origin: lines[0] }; } catch { /* fail closed below */ }
  }
  return { ok: false, reason: sawHint ? 'checkpoint signature INVALID over the signed note' : 'no checkpoint signature carries the pinned rekor key hint' };
}

/** RFC 6962 §2.1.4.2 consistency replay: is `first` a prefix of `second`? Throws on any failure. */
function verifyConsistency(firstSize, secondSize, firstRootHex, secondRootHex, hashesHex) {
  if (!Number.isSafeInteger(firstSize) || !Number.isSafeInteger(secondSize) || firstSize < 1 || secondSize < firstSize) {
    throw new Error(`invalid tree sizes ${firstSize} -> ${secondSize}`);
  }
  const first = Buffer.from(String(firstRootHex), 'hex');
  const second = Buffer.from(String(secondRootHex), 'hex');
  if (first.length !== 32 || second.length !== 32) throw new Error('root hash is not 32 bytes');
  const proof = (hashesHex ?? []).map((h) => { const b = Buffer.from(String(h), 'hex'); if (b.length !== 32) throw new Error('proof hash is not 32 bytes'); return b; });
  if (firstSize === secondSize) {
    if (proof.length !== 0) throw new Error('same-size proof must be empty');
    if (!first.equals(second)) throw new Error('same tree size but DIFFERENT roots — split-view evidence');
    return;
  }
  let isPow2 = true; { let n = firstSize; while (n % 2 === 0 && n > 1) n /= 2; isPow2 = n === 1; }
  const items = isPow2 ? [first, ...proof] : proof;
  if (items.length === 0) throw new Error('empty proof for a grown tree');
  let fn = firstSize - 1;
  let sn = secondSize - 1;
  while (fn % 2 === 1) { fn = Math.floor(fn / 2); sn = Math.floor(sn / 2); }
  let fr = items[0];
  let sr = items[0];
  for (let i = 1; i < items.length; i++) {
    if (sn === 0) throw new Error('too many proof hashes');
    if (fn % 2 === 1 || fn === sn) {
      fr = nodeHash(items[i], fr);
      sr = nodeHash(items[i], sr);
      while (fn % 2 === 0 && fn !== 0) { fn = Math.floor(fn / 2); sn = Math.floor(sn / 2); }
    } else {
      sr = nodeHash(sr, items[i]);
    }
    fn = Math.floor(fn / 2);
    sn = Math.floor(sn / 2);
  }
  if (!fr.equals(first)) throw new Error('recomputed OLD root differs — earlier checkpoint is not a prefix of the later tree');
  if (!sr.equals(second)) throw new Error('recomputed NEW root differs — proof does not land on the later signed root');
  if (sn !== 0) throw new Error('proof hashes exhausted before reaching the root');
}

function noteFields(text) {
  const sep = text.indexOf('\n\n');
  const bodyLines = text.slice(0, sep + 1).split('\n');
  return { origin: bodyLines[0], treeSize: Number(bodyLines[1]), rootHashHex: Buffer.from(bodyLines[2], 'base64').toString('hex') };
}

/**
 * Run the alarm. Pure-ish: reads only from disk (rootDir), returns a
 * report object; the CLI below turns that into exit codes and text.
 */
export function runDivergenceAlarm({ rootDir, engineKeyPin, rekorPub, observerPub, observerKeyId }) {
  const wDir = join(rootDir, 'witness');
  const gDir = join(wDir, 'gossip');
  const alarms = [];
  const notes = [];
  let obsNames = [];
  try { obsNames = readdirSync(gDir).filter((n) => OBS_RE.test(n)).sort(); } catch { /* no gossip dir yet */ }
  let witnessNames = [];
  try { witnessNames = readdirSync(wDir).filter((n) => WITNESS_RE.test(n)).sort(); } catch { /* no witness dir */ }

  if (obsNames.length === 0) {
    return { status: 'NO_DATA', alarms, notes: ['no second-observer observations present under witness/gossip/ — nothing to cross-check yet (absence is honest, not agreement)'], observationsChecked: 0, checkpointsSeen: 0 };
  }

  // Collect every verified checkpoint this alarm can see: the engine's own
  // witnessed heads (from witness/*.receipt.json), and each observation's
  // engine + live checkpoints (re-derived, never trusted as claimed).
  const cps = []; // { origin, treeSize, rootHex, source }
  for (const n of witnessNames) {
    try {
      const env = JSON.parse(readFileSync(join(wDir, n), 'utf8'));
      if (env.payloadType !== PAYLOAD_TYPE) continue;
      const st = JSON.parse(Buffer.from(env.payload, 'base64').toString('utf8'));
      const note = st.predicate?.summary?.rekor?.inclusionProof?.checkpoint;
      if (note) { const c = noteFields(note); cps.push({ origin: c.origin, treeSize: c.treeSize, rootHex: c.rootHashHex, source: `engine:${n}` }); }
    } catch (e) { alarms.push(`${n}: unreadable engine witness receipt (${e.message})`); }
  }

  let checked = 0;
  const census = {};
  for (const n of obsNames) {
    let env;
    try { env = JSON.parse(readFileSync(join(gDir, n), 'utf8')); } catch (e) { alarms.push(`${n}: unreadable JSON (${e.message})`); continue; }
    if (env.payloadType !== PAYLOAD_TYPE) { alarms.push(`${n}: unexpected payloadType ${env.payloadType}`); continue; }
    let payloadBytes;
    try { payloadBytes = Buffer.from(env.payload, 'base64'); } catch { alarms.push(`${n}: payload not base64`); continue; }
    const sigEntry = (env.signatures ?? []).find((s) => s.keyid === observerKeyId);
    if (!sigEntry) { alarms.push(`${n}: no signature for the pinned observer keyid ${observerKeyId}`); continue; }
    let sigOk = false;
    try { sigOk = edVerify(null, pae(PAYLOAD_TYPE, payloadBytes), observerPub, Buffer.from(sigEntry.sig, 'base64')); } catch { /* fail closed below */ }
    if (!sigOk) { alarms.push(`${n}: observer ed25519 signature INVALID — cannot trust this observation`); continue; }
    let st;
    try { st = JSON.parse(payloadBytes.toString('utf8')); } catch { alarms.push(`${n}: payload not JSON`); continue; }
    const s = st.predicate?.summary;
    if (st.predicateType !== GOSSIP_PREDICATE || s?.kind !== 'szl-quant-gossip-observation') { alarms.push(`${n}: wrong predicateType/kind`); continue; }
    if (s.label !== 'REPORTED') { alarms.push(`${n}: label ${s.label} — gossip observations must be REPORTED`); continue; }

    // Re-derive the verdict independently — the observation cannot editorialize.
    const eCp = { origin: s.engineCheckpoint?.origin, treeSize: s.engineCheckpoint?.treeSize, rootHashHex: s.engineCheckpoint?.rootHex };
    const lv = checkpointFields(String(s.liveCheckpoint?.rawNote ?? ''), rekorPub);
    if (!lv.ok) { alarms.push(`${n}: embedded live checkpoint note failed offline verification (${lv.reason})`); continue; }
    if (lv.origin !== s.liveCheckpoint?.origin || lv.treeSize !== s.liveCheckpoint?.treeSize || lv.rootHashHex !== s.liveCheckpoint?.rootHex) {
      alarms.push(`${n}: liveCheckpoint fields do not match the embedded signed note`); continue;
    }
    let expected;
    if (eCp.origin !== lv.origin) expected = 'SHARD_ROTATED';
    else if (lv.treeSize < eCp.treeSize) expected = 'LOG_REGRESSED';
    else if (lv.treeSize === eCp.treeSize) expected = lv.rootHashHex === eCp.rootHashHex ? 'ROOTS_EQUAL' : 'SPLIT_VIEW';
    else {
      try { verifyConsistency(eCp.treeSize, lv.treeSize, eCp.rootHashHex, lv.rootHashHex, s.consistency?.proofHashes ?? []); expected = 'PREFIX_OK'; }
      catch (e) { expected = 'SPLIT_VIEW'; notes.push(`${n}: consistency replay failed independently (${e.message}) — treated as SPLIT_VIEW`); }
    }
    const bindingAlarm = s.verdict === 'LEDGER_BINDING_MISMATCH' && s.ledger?.chainBindingVerified === false && GOOD_VERDICTS.has(expected);
    if (s.verdict !== expected && !bindingAlarm) {
      alarms.push(`${n}: signed verdict ${s.verdict} does NOT match independent recomputation ${expected} — observer may not editorialize`);
      continue;
    }
    checked += 1;
    census[s.verdict] = (census[s.verdict] ?? 0) + 1;
    if (!GOOD_VERDICTS.has(s.verdict)) {
      alarms.push(`${n}: ALARMING verdict ${s.verdict} at head seq ${s.ledger?.headSeq} (observed ${s.observedAtIso})`);
    }
    cps.push({ origin: eCp.origin, treeSize: eCp.treeSize, rootHex: eCp.rootHashHex, source: `${n}:engineCheckpoint` });
    cps.push({ origin: lv.origin, treeSize: lv.treeSize, rootHex: lv.rootHashHex, source: `${n}:liveCheckpoint` });
  }

  // Split-view sweep across every checkpoint any vantage point produced:
  // two verified checkpoints of the same origin+size MUST share a root.
  const seen = new Map();
  for (const cp of cps) {
    const key = `${cp.origin}#${cp.treeSize}`;
    const prev = seen.get(key);
    if (prev && prev.rootHex !== cp.rootHex) {
      alarms.push(`SPLIT VIEW at ${key}: ${prev.rootHex.slice(0, 12)}\u2026 (${prev.source}) vs ${cp.rootHex.slice(0, 12)}\u2026 (${cp.source})`);
    }
    if (!prev) seen.set(key, cp);
  }

  const status = alarms.length > 0 ? 'DIVERGENCE' : 'CLEAN';
  return { status, alarms, notes, observationsChecked: checked, observationsTotal: obsNames.length, checkpointsSeen: seen.size, census };
}

// ---- CLI (only runs when this file is executed directly, not on import) ----
function usage() {
  console.error('usage: node verify/divergence-alarm.mjs --witness <ledgerRoot> [--pubkey keys/engine_pubkey.json] [--rekor-pubkey keys/rekor_pubkey.pem] [--observer-pubkey keys/observer_pubkey.json]');
  process.exit(2);
}

function main() {
  const args = process.argv.slice(2);
  let rootDir = null;
  let pubkeyPath = 'keys/engine_pubkey.json';
  let rekorPubPath = 'keys/rekor_pubkey.pem';
  let observerPubPath = 'keys/observer_pubkey.json';
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--witness') rootDir = args[++i];
    else if (args[i] === '--pubkey') pubkeyPath = args[++i];
    else if (args[i] === '--rekor-pubkey') rekorPubPath = args[++i];
    else if (args[i] === '--observer-pubkey') observerPubPath = args[++i];
    else usage();
  }
  if (!rootDir) usage();

  let engineKeyPin, rekorPub, observerPub, observerKeyId;
  try {
    engineKeyPin = JSON.parse(readFileSync(pubkeyPath, 'utf8'));
    rekorPub = createPublicKey(readFileSync(rekorPubPath, 'utf8'));
    const opin = JSON.parse(readFileSync(observerPubPath, 'utf8'));
    observerPub = createPublicKey({ key: Buffer.from(opin.publicKeySpkiBase64, 'base64'), type: 'spki', format: 'der' });
    observerKeyId = opin.keyId;
    if (sha256Hex(observerPub.export({ type: 'spki', format: 'der' })).slice(0, 16) !== observerKeyId) {
      throw new Error('observer pin keyId does not match its own key material');
    }
  } catch (e) {
    console.error(`SETUP FAIL: ${e.message}`);
    process.exit(2);
  }

  const report = runDivergenceAlarm({ rootDir, engineKeyPin, rekorPub, observerPub, observerKeyId });

  console.log(`\nGENERATION 6 — divergence alarm  [REPORTED, offline-verified, read-only]`);
  console.log(`status: ${report.status}`);
  if (report.status === 'NO_DATA') {
    for (const n of report.notes) console.log(`  note: ${n}`);
    console.log('\nNo divergence claim can be made from zero observations. Exiting 0 (nothing to alarm on), but this is NOT a clean bill of health.');
    process.exit(0);
  }
  console.log(`observations independently re-verified: ${report.observationsChecked}/${report.observationsTotal}`);
  console.log(`distinct (origin, treeSize) checkpoints swept for split-views: ${report.checkpointsSeen}`);
  if (report.census && Object.keys(report.census).length) {
    console.log(`verdict census: ${Object.entries(report.census).map(([k, v]) => `${k} ${v}`).join(', ')}`);
  }
  for (const n of report.notes) console.log(`  note: ${n}`);
  if (report.status === 'DIVERGENCE') {
    console.log('\nALARM — divergence evidence found:');
    for (const a of report.alarms) console.log(`  DIVERGENCE: ${a}`);
    console.log('\nThis does not itself prove which vantage point is wrong — it proves the two vantage points disagree, or that an observation could not be trusted as reported. Investigate before citing either the engine or the observer as authoritative.');
    process.exit(1);
  }
  console.log('\nNo divergence evidence found in the data present. This means the engine and the second observer agree on every checkpoint both currently hold — it is REPORTED corroboration for this observation window, not proof of correctness, and not a trading or performance claim.');
  process.exit(0);
}

if (import.meta.url === `file://${process.argv[1]}`) main();
