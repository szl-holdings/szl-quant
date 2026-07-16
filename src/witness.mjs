/**
 * witness.mjs — external witness: anchor sealed chain heads in the
 * Sigstore Rekor public transparency log (rekor.sigstore.dev).
 *
 * The hash chain's confessed honest limit is head truncation: wholesale
 * deletion of the newest link(s) is locally undetectable. Witnessing
 * closes that gap for every anchored head: the head's exact bytes are
 * ed25519-signed and submitted to an append-only, publicly operated log.
 * Once integrated, the anchor cannot be unpublished — deleting the local
 * ledger does not delete the Rekor entry, and the entry stays
 * discoverable by this engine's public key.
 *
 * Doctrine: Rekor's response is REPORTED (an external service's
 * statement). What makes it usable offline is the SET — Rekor's own
 * ECDSA signature over {body, integratedTime, logID, logIndex} —
 * verifiable against the pinned Rekor public key with zero network.
 * The witness receipt stores everything needed for that offline replay.
 *
 * Entry type is `rekord` (full content), not `hashedrekord`: PureEdDSA
 * signs the raw message, so Rekor can only server-side-verify an ed25519
 * signature when it has the artifact bytes. The chain receipt is public
 * data in a public repo — submitting its bytes discloses nothing.
 *
 * HONEST LIMITS (stated in every receipt):
 * - Only witnessed heads are protected; coverage gaps (Rekor outages)
 *   are counted in the open, never papered over.
 * - SET proves Rekor ACCEPTED the entry at integratedTime; Merkle
 *   inclusion against a signed tree head is NOT verified offline here.
 */
import { canonicalBytes } from './canonical-json.mjs';

export const WITNESS_FILE_RE = /^witness_\d{4}_\d+\.receipt\.json$/;
export const REKOR_SERVER = 'https://rekor.sigstore.dev';

export function witnessFileName(seq, nowMs) {
  return `witness_${String(seq).padStart(4, '0')}_${nowMs}.receipt.json`;
}

/** Proposed rekord entry: full artifact content + raw ed25519 sig + SPKI PEM. */
export function buildRekordProposal({ artifactBytes, signatureBase64, publicKeyPem }) {
  return {
    apiVersion: '0.0.1',
    kind: 'rekord',
    spec: {
      data: { content: Buffer.from(artifactBytes).toString('base64') },
      signature: {
        format: 'x509',
        content: signatureBase64,
        publicKey: { content: Buffer.from(publicKeyPem, 'utf8').toString('base64') },
      },
    },
  };
}

/**
 * The exact bytes Rekor signs in its SET: RFC 8785-canonical JSON of
 * exactly these four fields (alphabetical keys, no whitespace).
 */
export function setMessageBytes({ entryBodyBase64, integratedTime, logID, logIndex }) {
  return canonicalBytes({ body: entryBodyBase64, integratedTime, logID, logIndex });
}

/**
 * Pull verifier-relevant fields from a canonicalized rekord entry body
 * (Rekor strips data.content and stores data.hash). Null on shape miss —
 * callers fail closed.
 */
export function extractRekordFields(entryBodyBase64) {
  let e;
  try { e = JSON.parse(Buffer.from(entryBodyBase64, 'base64').toString('utf8')); } catch { return null; }
  if (e?.kind !== 'rekord') return null;
  const hash = e.spec?.data?.hash;
  const sig = e.spec?.signature;
  if (hash?.algorithm !== 'sha256' || !hash?.value || !sig?.content || !sig?.publicKey?.content) return null;
  return {
    dataSha256: hash.value,
    signatureBase64: sig.content,
    publicKeyPemBase64: sig.publicKey.content,
    format: sig.format ?? null,
  };
}

/** Signed witness receipt body (pure; IO and network live in bin/). */
export function buildWitnessBody({ chain, rekor, nowIso }) {
  return {
    kind: 'szl-quant-witness',
    generatedAtIso: nowIso,
    chain: { seq: chain.seq, runDir: chain.runDir, file: chain.file, sha256: chain.sha256 },
    rekor: {
      server: rekor.server,
      uuid: rekor.uuid,
      logIndex: rekor.logIndex,
      logID: rekor.logID,
      integratedTime: rekor.integratedTime,
      entryBodyBase64: rekor.entryBodyBase64,
      signedEntryTimestampBase64: rekor.signedEntryTimestampBase64,
    },
    labels: {
      anchor: 'REPORTED',
      note: 'rekor integration data is an external service statement; its SET is offline-verifiable against the pinned rekor public key',
    },
    note: 'external witness: this sealed chain head is anchored in a public append-only transparency log — deleting the ledger does not delete the anchor',
    limits: [
      'protects only witnessed heads; coverage gaps (rekor outages) are counted, not hidden',
      'SET proves rekor accepted the entry at integratedTime; Merkle inclusion proof is not verified offline here',
    ],
  };
}
