/**
 * gates.mjs — fail-closed risk gates. Every gate returns a verdict object:
 *   { gate, verdict: 'ALLOWED' | 'BLOCKED', reason, evidence? }
 * A BLOCKED verdict is emitted as BLOCKED — never flipped, never hidden.
 * Missing/uncertain inputs BLOCK (fail closed), they never pass silently.
 */
import { VERDICTS, TRUST_CEILING, POSTURE } from './canon.mjs';

function allowed(gate, reason, evidence) {
  return { gate, verdict: VERDICTS.ALLOWED, reason, ...(evidence ? { evidence } : {}) };
}
function blocked(gate, reason, evidence) {
  return { gate, verdict: VERDICTS.BLOCKED, reason, ...(evidence ? { evidence } : {}) };
}

/** Data freshness: timestamps must exist and be within maxAgeMs. */
export function freshnessGate(observedAtMs, nowMs, maxAgeMs) {
  if (!Number.isFinite(observedAtMs) || !Number.isFinite(nowMs)) {
    return blocked('freshness', 'missing observation timestamp (fail closed)');
  }
  const age = nowMs - observedAtMs;
  if (age < 0) return blocked('freshness', 'observation timestamp in the future (clock skew — fail closed)', { ageMs: age });
  if (age > maxAgeMs) return blocked('freshness', `data stale: age ${age}ms > max ${maxAgeMs}ms`, { ageMs: age, maxAgeMs });
  return allowed('freshness', `age ${age}ms within ${maxAgeMs}ms`, { ageMs: age, maxAgeMs });
}

/** Sample size: need at least minObs observations to say anything. */
export function sampleSizeGate(nObs, minObs) {
  if (!Number.isFinite(nObs)) return blocked('sample-size', 'observation count unknown (fail closed)');
  if (nObs < minObs) return blocked('sample-size', `insufficient history: ${nObs} < ${minObs} observations`, { nObs, minObs });
  return allowed('sample-size', `${nObs} observations ≥ ${minObs}`, { nObs, minObs });
}

/** Liquidity (live pairs): 24h volume and liquidity USD must clear floors. */
export function liquidityGate(liquidityUsd, volume24hUsd, minLiquidityUsd, minVolumeUsd) {
  if (!Number.isFinite(liquidityUsd) || !Number.isFinite(volume24hUsd)) {
    return blocked('liquidity', 'liquidity/volume unknown (fail closed)');
  }
  if (liquidityUsd < minLiquidityUsd) {
    return blocked('liquidity', `pool liquidity $${liquidityUsd.toFixed(0)} < floor $${minLiquidityUsd}`, { liquidityUsd, minLiquidityUsd });
  }
  if (volume24hUsd < minVolumeUsd) {
    return blocked('liquidity', `24h volume $${volume24hUsd.toFixed(0)} < floor $${minVolumeUsd}`, { volume24hUsd, minVolumeUsd });
  }
  return allowed('liquidity', 'liquidity and volume clear floors', { liquidityUsd, volume24hUsd });
}

/** Volatility ceiling: refuse signals when realized vol exceeds the cap. */
export function volatilityGate(annVol, maxAnnVol) {
  if (!Number.isFinite(annVol)) return blocked('volatility', 'realized volatility unknown (fail closed)');
  if (annVol > maxAnnVol) return blocked('volatility', `annualized vol ${(annVol * 100).toFixed(1)}% > cap ${(maxAnnVol * 100).toFixed(0)}%`, { annVol, maxAnnVol });
  return allowed('volatility', `annualized vol ${(annVol * 100).toFixed(1)}% within cap`, { annVol, maxAnnVol });
}

/** Conviction floor: Λ conviction must clear the floor (and the ceiling law). */
export function convictionGate(conviction, floor) {
  if (!Number.isFinite(conviction)) return blocked('conviction', 'no conviction computable (fail closed)');
  if (conviction > TRUST_CEILING) return blocked('conviction', `conviction ${conviction} exceeds trust ceiling ${TRUST_CEILING} — doctrine violation (fail closed)`);
  if (conviction < floor) return blocked('conviction', `conviction ${conviction.toFixed(4)} < floor ${floor}`, { conviction, floor });
  return allowed('conviction', `conviction ${conviction.toFixed(4)} ≥ floor ${floor}`, { conviction, floor });
}

/** Loop-tax budget: the ouroboros ledger must have budget remaining. */
export function loopTaxGate(ledger) {
  if (!ledger || !Number.isFinite(ledger.remaining)) return blocked('loop-tax', 'loop-tax ledger missing (fail closed)');
  if (ledger.remaining <= 0) return blocked('loop-tax', `governance budget exhausted (spent ${ledger.spent}/${ledger.budget})`, { ...ledger });
  return allowed('loop-tax', `budget remaining ${ledger.remaining}/${ledger.budget}`, { ...ledger });
}

/** Posture gate: structurally asserts paper-only advisory mode. */
export function postureGate() {
  if (POSTURE.execution !== false || POSTURE.custody !== false) {
    return blocked('posture', 'engine posture is not paper-only — refusing to emit (fail closed)');
  }
  return allowed('posture', 'ADVISORY_PAPER_ONLY posture verified; no execution/custody code paths');
}

/** Run all gates; overall verdict is BLOCKED if ANY gate blocks. */
export function runGates(gateResults) {
  const blockedGates = gateResults.filter((g) => g.verdict === VERDICTS.BLOCKED);
  return {
    verdict: blockedGates.length ? VERDICTS.BLOCKED : VERDICTS.ALLOWED,
    gates: gateResults,
    blockedBy: blockedGates.map((g) => g.gate),
  };
}
