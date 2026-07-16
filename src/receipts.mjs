/**
 * receipts.mjs — every emitted signal/decision/backtest wraps in a
 * DSSE-signed in-toto Statement (govsign pattern, khipu key convention).
 *
 * predicateTypes:
 *   https://szl.holdings/quant/signal/v1    — one advisory signal decision
 *   https://szl.holdings/quant/backtest/v1  — one MEASURED backtest run
 *   https://szl.holdings/quant/session/v1   — one live paper session cycle
 *
 * Doctrine invariants baked into every predicate:
 *   posture ADVISORY_PAPER_ONLY, provenTrust locked false, trust ceiling
 *   0.97, BLOCKED verdicts signed as BLOCKED, Λ = Conjecture 1 (advisory).
 */
import { createHash } from 'node:crypto';
import { canonicalBytes } from './canonical-json.mjs';
import { signEnvelope } from './dsse.mjs';
import { POSTURE, TRUST_CEILING, LAMBDA_STATUS, LOCKED_PROVEN_FORMULA_IDS } from './canon.mjs';

export const IN_TOTO_STATEMENT = 'https://in-toto.io/Statement/v1';
export const PREDICATE = Object.freeze({
  signal: 'https://szl.holdings/quant/signal/v1',
  backtest: 'https://szl.holdings/quant/backtest/v1',
  session: 'https://szl.holdings/quant/session/v1',
  track: 'https://szl.holdings/quant/track-record/v1',
  chain: 'https://szl.holdings/quant/chain/v1',
  book: 'https://szl.holdings/quant/book/v1',
  refusals: 'https://szl.holdings/quant/refusals/v1',
});

function sha256Hex(obj) {
  return createHash('sha256').update(canonicalBytes(obj)).digest('hex');
}

/** Common doctrine block — present in every predicate; verifier enforces it. */
export function doctrineBlock() {
  return {
    doctrine: 'v11',
    posture: { ...POSTURE },                       // provenTrust: false — no code path sets it true
    trustCeiling: TRUST_CEILING,
    lambdaStatus: LAMBDA_STATUS,
    lockedProvenFormulaIds: [...LOCKED_PROVEN_FORMULA_IDS],
    lockedProvenMappingNote: 'local formula implementations are NOT asserted to map onto the locked-proven F-ids (UNKNOWN — never fabricated)',
    disclaimer: 'Advisory research output. Paper-only. NOT financial advice. No execution, no custody.',
  };
}

/**
 * Build + sign a receipt. `subjectName` names the decision object; the
 * subject digest pins the exact canonical bytes of `subjectBody`.
 */
export function signReceipt({ predicateType, subjectName, subjectBody, predicate, privateKey, publicKey }) {
  const statement = {
    _type: IN_TOTO_STATEMENT,
    subject: [{ name: subjectName, digest: { sha256: sha256Hex(subjectBody) } }],
    predicateType,
    predicate: { ...predicate, _doctrine: doctrineBlock() },
  };
  return { statement, envelope: signEnvelope(statement, privateKey, publicKey) };
}
