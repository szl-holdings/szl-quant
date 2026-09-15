/**
 * engine.mjs — the governed cycle: ingest → signal → gates → paper account,
 * inside an ouroboros bounded loop, every decision DSSE-receipted.
 */
import { evaluate } from './strategy.mjs';
import { annualizedVol } from './formulas.mjs';
import {
  freshnessGate, sampleSizeGate, liquidityGate, volatilityGate,
  convictionGate, loopTaxGate, postureGate, runGates,
} from './gates.mjs';
import { makeLoopTaxLedger, chargeLoopTax } from './ouroboros.mjs';
import { signReceipt, PREDICATE } from './receipts.mjs';
import { VERDICTS } from './canon.mjs';

export const DEFAULT_PARAMS = Object.freeze({
  momentumLookback: 28,
  zWindow: 20,
  zEntry: 1.0,
  volWindow: 30,
  positionFraction: 0.2,
});

export const DEFAULT_LIMITS = Object.freeze({
  maxAnnVol: 3.5,              // 350% annualized — memecoins beyond this BLOCK
  convictionFloor: 0.55,
  minLiquidityUsd: 250_000,
  minVolume24hUsd: 100_000,
  maxSnapshotAgeMs: 5 * 60_000,
  minObservations: 45,
});

/**
 * Decide on one LIVE pair snapshot + its daily history context.
 * Always returns a signed receipt — ALLOWED signals AND BLOCKED verdicts.
 */
export function decideLive({ pair, history, params = DEFAULT_PARAMS, limits = DEFAULT_LIMITS, ledger, nowMs, keys }) {
  const gates = [postureGate(), loopTaxGate(ledger)];
  gates.push(freshnessGate(pair.observedAtMs, nowMs, limits.maxSnapshotAgeMs));
  gates.push(liquidityGate(pair.liquidityUsd, pair.volume24hUsd, limits.minLiquidityUsd, limits.minVolume24hUsd));

  let signal = null;
  let vol = null;
  if (history?.ok) {
    gates.push(sampleSizeGate(history.series.length, limits.minObservations));
    vol = annualizedVol(history.series.map((s) => s.close), params.volWindow);
    gates.push(volatilityGate(vol, limits.maxAnnVol));
    signal = evaluate(history.series, params);
    if (signal.action === 'ENTER_LONG') gates.push(convictionGate(signal.conviction, limits.convictionFloor));
  } else {
    gates.push({ gate: 'history', verdict: VERDICTS.BLOCKED, reason: history?.unavailable?.note ?? 'history feed UNAVAILABLE (fail closed)' });
  }

  const overall = runGates(gates);
  const decision = {
    asset: { symbol: pair.baseSymbol, address: pair.baseAddress, chain: pair.chainId, dex: pair.dexId },
    snapshot: { label: 'REPORTED', priceUsd: pair.priceUsd, liquidityUsd: pair.liquidityUsd, volume24hUsd: pair.volume24hUsd, observedAtIso: new Date(pair.observedAtMs).toISOString() },
    proposedAction: signal?.action ?? 'ABSTAIN',
    conviction: signal?.conviction ?? null,
    components: signal?.components ?? null,
    verdict: overall.verdict,                    // BLOCKED stays BLOCKED
    blockedBy: overall.blockedBy,
    gates: overall.gates,
    loopTax: { budget: ledger.budget, spent: ledger.spent, remaining: ledger.remaining },
  };

  const { statement, envelope } = signReceipt({
    predicateType: PREDICATE.signal,
    subjectName: `szl-quant/signal/${pair.baseSymbol ?? 'unknown'}/${new Date(nowMs).toISOString()}`,
    subjectBody: decision,
    predicate: { decision },
    privateKey: keys.privateKey,
    publicKey: keys.publicKey,
  });
  return { decision, statement, envelope };
}

export { makeLoopTaxLedger, chargeLoopTax };

/** Research-only preflight for the existing A11oy/Hatun agent boundary.
 * Uses ingestion-supplied temporal records and an independently maintained
 * compute-budget snapshot. Never pass an agent's guessed timestamps as evidence.
 * REVIEW requests further review; it does not authenticate inputs, grant paper
 * fills, sign a receipt, reserve budget, or permit real-money execution.
 */
export async function reviewResearchInputs({ observations, decisionAtMs, maxEventAgeMs, researchBudget } = {}) {
  const { pointInTimeGate, researchBudgetGate } = await import('./gates.mjs');
  const result = runGates([
    postureGate(), pointInTimeGate(observations, decisionAtMs, maxEventAgeMs),
    researchBudgetGate(researchBudget),
  ]);
  return {
    schema: 'szl.quant.research-preflight/v1',
    disposition: result.verdict === VERDICTS.ALLOWED ? 'REVIEW' : 'ABSTAIN',
    gates: result.gates,
    blockedBy: result.blockedBy,
    canonicalPaperEngine: 'szl-holdings/szl-quant',
    evidenceAuthenticationVerified: false,
    budgetReservationPerformed: false,
    paperFillAuthorized: false,
    realMoneyExecutionAuthorized: false,
    ledgerMutationPerformed: false,
  };
}
