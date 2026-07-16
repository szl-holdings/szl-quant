/**
 * gossip.mjs — cross-witness gossip (generation 5): verify and account for
 * signed observations published by the second observer,
 * szl-holdings/szl-quant-witness.
 *
 * The observer watches from its own vantage point: it clones the public
 * ledger, re-verifies the head binding, captures Rekor's LIVE checkpoint as
 * it sees it, replays the consistency proof from the engine-captured
 * checkpoint to the live one BEFORE signing, and publishes a DSSE-signed
 * observation. This module is the engine-side counterpart: full offline
 * re-verification of every claim inside an observation, verdict
 * recomputation (an observer cannot sign a rosy verdict over alarming
 * data), and split-view sweeping across every checkpoint both parties hold.
 *
 * Pure functions only — IO and network live in bin/. The independent
 * verifier mirrors these checks without importing this module.
 *
 * Honesty: observations are REPORTED. Both repos share one GitHub org and
 * one maintainer — the observer adds a second vantage point, schedule and
 * key, NOT a second operator. Every surface that mentions gossip says so.
 */
import { createHash } from 'node:crypto';
import { verifyEnvelope } from './dsse.mjs';
import { loadPublicKeyFromSpkiBase64 } from './keys.mjs';
import { IN_TOTO_STATEMENT } from './receipts.mjs';
import { parseCheckpoint, verifyCheckpoint, rfc6962VerifyConsistency } from './witness.mjs';

export const GOSSIP_OBSERVATION_PREDICATE = 'https://szl.holdings/quant/gossip-observation/v1';
export const OBS_FILE_RE = /^obs_(\d{4})_\d+\.observation\.json$/;
export const GOSSIP_FILE_RE = /^gossip_(\d{4})_(\d+)\.receipt\.json$/;
export const GOSSIP_SOURCE = Object.freeze({
  repo: 'szl-holdings/szl-quant-witness',
  branch: 'observations',
  dir: 'observations',
});
export const OBSERVATION_KIND = 'szl-quant-gossip-observation';
export const GOOD_VERDICTS = Object.freeze(['PREFIX_OK', 'ROOTS_EQUAL']);

export function gossipFileName(seq, nowMs) {
  return `gossip_${String(seq).padStart(4, '0')}_${nowMs}.receipt.json`;
}

const sha256Hex = (b) => createHash('sha256').update(b).digest('hex');

/** Deterministic verdict recomputation from verified checkpoint data. */
export function recomputeVerdict({ engineCp, liveCp, proofHashes }) {
  if (engineCp.origin !== liveCp.origin) return 'SHARD_ROTATED';
  if (liveCp.treeSize < engineCp.treeSize) return 'LOG_REGRESSED';
  if (liveCp.treeSize === engineCp.treeSize) {
    return liveCp.rootHex === engineCp.rootHex ? 'ROOTS_EQUAL' : 'SPLIT_VIEW';
  }
  try {
    rfc6962VerifyConsistency({
      firstSize: engineCp.treeSize, secondSize: liveCp.treeSize,
      firstRootHex: engineCp.rootHex, secondRootHex: liveCp.rootHex,
      proofHex: proofHashes ?? [],
    });
    return 'PREFIX_OK';
  } catch {
    return 'SPLIT_VIEW';
  }
}

/**
 * Fully re-verify one signed observation, offline.
 * Caller resolves local bytes: witnessReceiptBytes (the witness receipt the
 * observation claims to be about) and chainSha256Local (sha256 of the chain
 * link file the observation names) — pass null when absent; absence fails
 * closed with an honest reason.
 * Returns { ok, reason?, seq?, verdict?, observedAtIso?, liveCp? }.
 */
export function verifyObservation({ envelope, observerPubkeyJson, rekorPem, witnessReceiptBytes, chainSha256Local }) {
  try {
    const pin = observerPubkeyJson;
    if (!pin || pin.alg !== 'ed25519' || !pin.publicKeySpkiBase64 || !pin.keyId) {
      return { ok: false, reason: 'observer public key pin missing or malformed — refusing to trust an unpinned observer' };
    }
    const pub = loadPublicKeyFromSpkiBase64(pin.publicKeySpkiBase64);
    const v = verifyEnvelope(envelope, pub);
    if (!v.ok) return { ok: false, reason: `observation DSSE verification failed: ${v.reason}` };
    const st = v.payload;
    if (st._type !== IN_TOTO_STATEMENT) return { ok: false, reason: 'not an in-toto Statement' };
    if (st.predicateType !== GOSSIP_OBSERVATION_PREDICATE) return { ok: false, reason: `unexpected predicateType ${st.predicateType}` };
    const s = st.predicate?.summary;
    if (!s || s.kind !== OBSERVATION_KIND) return { ok: false, reason: `unexpected observation kind ${s?.kind}` };
    if (s.label !== 'REPORTED') return { ok: false, reason: `observation label must be REPORTED, got ${s.label}` };
    if (!Array.isArray(s.limits) || s.limits.length === 0) return { ok: false, reason: 'observation states no limits — canon requires honesty about limits' };
    if (s.observer?.repo !== GOSSIP_SOURCE.repo) return { ok: false, reason: `unexpected observer repo ${s.observer?.repo}` };
    if (s.observer?.keyId !== pin.keyId) return { ok: false, reason: `observer keyId ${s.observer?.keyId} does not match the pinned key ${pin.keyId}` };
    if (s.ledger?.repo !== 'szl-holdings/szl-quant' || s.ledger?.branch !== 'ledger') {
      return { ok: false, reason: `observation is not about this ledger (${s.ledger?.repo}@${s.ledger?.branch})` };
    }

    // subject binds the exact witness receipt bytes observed
    const subj = st.subject?.[0]?.digest?.sha256;
    if (subj !== s.ledger.witnessSha256) return { ok: false, reason: 'subject digest does not bind the observed witness receipt' };

    // local cross-binding: the observed witness receipt must exist HERE with the same bytes
    if (!witnessReceiptBytes) return { ok: false, reason: `observed witness receipt ${s.ledger.witnessFile} is absent from this ledger` };
    if (sha256Hex(witnessReceiptBytes) !== s.ledger.witnessSha256) {
      return { ok: false, reason: `witness receipt ${s.ledger.witnessFile} bytes DIFFER between this ledger and what the observer saw — divergent-history evidence` };
    }
    if (!chainSha256Local) return { ok: false, reason: `chain link ${s.ledger.chainFile} is absent from this ledger` };
    if (chainSha256Local !== s.ledger.chainSha256) {
      return { ok: false, reason: `chain link ${s.ledger.chainFile} bytes DIFFER between this ledger and what the observer saw — divergent-history evidence` };
    }
    if (s.ledger.chainBindingVerified !== true && GOOD_VERDICTS.includes(s.verdict)) {
      return { ok: false, reason: 'observer reported a failed chain binding but signed a good verdict' };
    }

    // the engine-captured checkpoint the observer claims: must equal what the
    // named witness receipt actually carries (parsed from OUR copy)
    const wSt = JSON.parse(Buffer.from(JSON.parse(witnessReceiptBytes.toString('utf8')).payload, 'base64').toString('utf8'));
    const eNote = wSt.predicate?.summary?.rekor?.inclusionProof?.checkpoint;
    if (!eNote) return { ok: false, reason: 'local witness receipt carries no checkpoint to cross-check against' };
    const eCp = parseCheckpoint(eNote);
    const claimedE = s.engineCheckpoint;
    if (claimedE.origin !== eCp.origin || claimedE.treeSize !== eCp.treeSize || claimedE.rootHex !== eCp.rootHashHex) {
      return { ok: false, reason: 'engineCheckpoint in the observation does not match the checkpoint inside the named witness receipt' };
    }

    // the LIVE checkpoint: replay Rekor's signature over the embedded note
    const rawNote = s.liveCheckpoint?.rawNote;
    if (typeof rawNote !== 'string') return { ok: false, reason: 'observation embeds no raw live checkpoint note — cannot replay Rekor signature offline' };
    const lv = verifyCheckpoint(rawNote, rekorPem);
    if (!lv.ok) return { ok: false, reason: `live checkpoint note failed offline verification: ${lv.reason}` };
    if (lv.origin !== s.liveCheckpoint.origin || lv.treeSize !== s.liveCheckpoint.treeSize || lv.rootHashHex !== s.liveCheckpoint.rootHex) {
      return { ok: false, reason: 'liveCheckpoint fields do not match the embedded signed note' };
    }

    // verdict recomputation — the observer cannot editorialize
    const expected = recomputeVerdict({
      engineCp: { origin: eCp.origin, treeSize: eCp.treeSize, rootHex: eCp.rootHashHex },
      liveCp: { origin: lv.origin, treeSize: lv.treeSize, rootHex: lv.rootHashHex },
      proofHashes: s.consistency?.proofHashes,
    });
    const signed = s.verdict;
    const bindingAlarm = signed === 'LEDGER_BINDING_MISMATCH' && s.ledger.chainBindingVerified === false && GOOD_VERDICTS.includes(expected);
    if (signed !== expected && !bindingAlarm) {
      return { ok: false, reason: `signed verdict ${signed} does not match offline recomputation ${expected}` };
    }
    return {
      ok: true, seq: s.ledger.headSeq, verdict: signed, observedAtIso: s.observedAtIso,
      liveCp: { origin: lv.origin, treeSize: lv.treeSize, rootHex: lv.rootHashHex, source: 'gossip-observation' },
    };
  } catch (e) {
    return { ok: false, reason: `observation verification error: ${e.message}` };
  }
}

/**
 * Split-view sweep across checkpoints from BOTH parties: any two checkpoints
 * of the same origin and tree size must share a root. Returns conflicts.
 */
export function sweepSplitViews(checkpoints) {
  const seen = new Map();
  const conflicts = [];
  for (const cp of checkpoints) {
    const key = `${cp.origin}#${cp.treeSize}`;
    const prev = seen.get(key);
    if (prev && prev.rootHex !== cp.rootHex) {
      conflicts.push({ origin: cp.origin, treeSize: cp.treeSize, roots: [prev.rootHex, cp.rootHex], sources: [prev.source, cp.source] });
    }
    if (!prev) seen.set(key, cp);
  }
  return conflicts;
}

/** Signed gossip-check receipt body (engine-side accounting of observations). */
export function buildGossipBody({ headSeq, fetchedAtIso, remoteTotal, newArchived, archivedTotal, rejected, census, newestObservation, nowIso }) {
  return {
    kind: 'szl-quant-gossip-check',
    label: 'REPORTED',
    source: { ...GOSSIP_SOURCE },
    headSeq,
    fetchedAtIso,
    observations: {
      remoteTotal,
      newArchived,
      archivedTotal,
      rejected: rejected.map((r) => ({ file: r.file, reason: r.reason })),
      verdictCensus: census,
    },
    newestObservation: newestObservation ?? null,
    generatedAtIso: nowIso,
    limits: [
      'the observer lives in the same GitHub org under the same maintainer — a second vantage point, schedule and signing key, NOT a second operator',
      'REPORTED: the observations branch is fetched over the network at witness time; every archived observation is fully re-verified offline before archiving, and again by the independent verifier',
      'observations the observer never published (outages, missed schedules) are visible as gaps in OBSERVATIONS.md and counted nowhere else — absence is honest',
    ],
    note: 'cross-witness gossip: a split view between what Rekor showed the engine and what it showed the second observer would surface here as a rejected observation or an alarming verdict — signed evidence either way',
  };
}
