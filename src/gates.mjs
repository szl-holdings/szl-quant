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
  if (!Number.isSafeInteger(observedAtMs) || observedAtMs < 0 || !Number.isSafeInteger(nowMs) || nowMs < 0 || !Number.isSafeInteger(maxAgeMs) || maxAgeMs < 0) {
    return blocked('freshness', 'invalid timestamp or freshness limit (fail closed)');
  }
  const age = nowMs - observedAtMs;
  if (age < 0) return blocked('freshness', 'observation timestamp in the future (clock skew — fail closed)', { ageMs: age });
  if (age > maxAgeMs) return blocked('freshness', `data stale: age ${age}ms > max ${maxAgeMs}ms`, { ageMs: age, maxAgeMs });
  return allowed('freshness', `age ${age}ms within ${maxAgeMs}ms`, { ageMs: age, maxAgeMs });
}

/** Sample size: need at least minObs observations to say anything. */
export function sampleSizeGate(nObs, minObs) {
  if (!Number.isSafeInteger(nObs) || nObs < 0 || !Number.isSafeInteger(minObs) || minObs <= 0) return blocked('sample-size', 'invalid observation count or sample floor (fail closed)');
  if (nObs < minObs) return blocked('sample-size', `insufficient history: ${nObs} < ${minObs} observations`, { nObs, minObs });
  return allowed('sample-size', `${nObs} observations ≥ ${minObs}`, { nObs, minObs });
}

/** Liquidity (live pairs): 24h volume and liquidity USD must clear floors. */
export function liquidityGate(liquidityUsd, volume24hUsd, minLiquidityUsd, minVolumeUsd) {
  if (![liquidityUsd, volume24hUsd, minLiquidityUsd, minVolumeUsd].every((value) => Number.isFinite(value) && value >= 0)) {
    return blocked('liquidity', 'liquidity, volume or policy floor invalid (fail closed)');
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
  if (!Number.isFinite(annVol) || annVol < 0 || !Number.isFinite(maxAnnVol) || maxAnnVol < 0) return blocked('volatility', 'invalid realized volatility or ceiling (fail closed)');
  if (annVol > maxAnnVol) return blocked('volatility', `annualized vol ${(annVol * 100).toFixed(1)}% > cap ${(maxAnnVol * 100).toFixed(0)}%`, { annVol, maxAnnVol });
  return allowed('volatility', `annualized vol ${(annVol * 100).toFixed(1)}% within cap`, { annVol, maxAnnVol });
}

/** Conviction floor: Λ conviction must clear the floor (and the ceiling law). */
export function convictionGate(conviction, floor) {
  if (!Number.isFinite(conviction) || conviction < 0 || !Number.isFinite(floor) || floor < 0 || floor > TRUST_CEILING) return blocked('conviction', 'invalid conviction or policy floor (fail closed)');
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

/** Require an explicit, nonempty, nonduplicated gate set with known verdicts.
 * This validates the returned set, not its completeness against an action schema.
 * Callers remain responsible for running every gate required by that action.
 * ALLOWED is the existing advisory-paper verdict; it grants no real execution.
 */
export function runGates(gateResults) {
  if (!Array.isArray(gateResults) || gateResults.length === 0 || gateResults.length > 128) {
    const refusal = blocked('gate-contract', 'missing or out-of-bound gate collection (fail closed)');
    return { verdict: VERDICTS.BLOCKED, gates: [refusal], blockedBy: ['gate-contract'] };
  }
  const names = new Set();
  const gates = Array.from(gateResults, (result, index) => {
    if (!result || typeof result !== 'object' || Array.isArray(result) ||
        typeof result.gate !== 'string' || !/^[a-z][a-z0-9-]{0,63}$/.test(result.gate) ||
        typeof result.reason !== 'string' || result.reason.trim().length === 0 ||
        ![VERDICTS.ALLOWED, VERDICTS.BLOCKED].includes(result.verdict)) {
      return blocked('gate-contract', `invalid gate result at index ${index} (fail closed)`);
    }
    if (names.has(result.gate)) {
      return blocked('gate-contract', `duplicate gate at index ${index}: ${result.gate} (fail closed)`);
    }
    names.add(result.gate);
    return result;
  });
  const refused = gates.filter((result) => result.verdict !== VERDICTS.ALLOWED);
  return { verdict: refused.length ? VERDICTS.BLOCKED : VERDICTS.ALLOWED,
    gates, blockedBy: [...new Set(refused.map((result) => result.gate))] };
}

/** Read-only temporal consistency check for factual research observations.
 * Times must be independently supplied by ingestion, never inferred by an LLM.
 * A consistent declaration is not authentication, signature verification, or
 * proof that no other context (model weights, retrieval, memory) leaks the future.
 */
export function pointInTimeGate(observations, decisionAtMs, maxEventAgeMs) {
  const stamp = (v) => Number.isSafeInteger(v) && v >= 0;
  if (!stamp(decisionAtMs) || !stamp(maxEventAgeMs) || !Array.isArray(observations) ||
      observations.length === 0 || observations.length > 512) {
    return blocked('point-in-time', 'missing or invalid time-bounded evidence collection');
  }
  const seen = new Set();
  for (let i = 0; i < observations.length; i += 1) {
    const row = observations[i];
    if (!row || typeof row !== 'object' || !/^[0-9a-f]{64}$/.test(row.contentSha256 ?? '') ||
        seen.has(row.contentSha256) ||
        ![row.eventAtMs, row.publishedAtMs, row.retrievedAtMs].every(stamp)) {
      return blocked('point-in-time', `invalid or duplicate evidence at index ${i}`);
    }
    seen.add(row.contentSha256);
    if (row.eventAtMs > row.publishedAtMs || row.publishedAtMs > row.retrievedAtMs ||
        row.retrievedAtMs > decisionAtMs) {
      return blocked('point-in-time', `inconsistent chronology or evidence unavailable by decision at index ${i}`);
    }
    // A fresh fetch cannot make an old market observation fresh.
    if (decisionAtMs - row.eventAtMs > maxEventAgeMs) {
      return blocked('point-in-time', `event outside the declared research freshness window at index ${i}`);
    }
  }
  return allowed('point-in-time', 'declared event/publication/retrieval times are consistent with the decision cutoff',
    { observations: observations.length, decisionAtMs, authenticationVerified: false });
}

/** Fixed-point research-compute budget check, not an external spend operation.
 * Micro-USD integers avoid floating subtraction; zero-cost work is representable.
 * The caller must atomically reserve budget before provider use and reconcile
 * actual invoices afterwards. This pure check neither reserves nor spends.
 */
export function researchBudgetGate(budget) {
  const fields = ['budgetMicroUsd', 'spentMicroUsd', 'reservedMicroUsd', 'estimatedNextMicroUsd'];
  if (!budget || typeof budget !== 'object' ||
      !fields.every((name) => Number.isSafeInteger(budget[name]) && budget[name] >= 0)) {
    return blocked('research-budget', 'research budget or estimate is absent or outside the integer domain');
  }
  const [total, spent, reserved, estimate] = fields.map((name) => BigInt(budget[name]));
  if (spent + reserved + estimate > total) {
    return blocked('research-budget', 'spent, outstanding reservations and next estimate exceed the research budget');
  }
  return allowed('research-budget', 'declared budget covers the next estimate; no funds reserved or spent',
    { projectedRemainingMicroUsd: Number(total - spent - reserved - estimate), reservationPerformed: false });
}
