/**
 * strategy.mjs — signals expressed through the formula canon.
 *
 * Two v1 strategies, both HEURISTIC by construction (their market
 * assumptions are not proven — see docs/METHODOLOGY.md):
 *   - tsmom: time-series momentum (lookback L days; long if trailing
 *     return > 0). Lineage: Moskowitz–Ooi–Pedersen TSMOM, adapted.
 *   - meanrev: z-score mean reversion (window W; long if z < -zEntry,
 *     exit when z ≥ 0). Adapted from standard stat-arb practice.
 *
 * Component scores in [0,1] are combined with Λ (lambdaAggregate, D2
 * weighted geometric mean) into a single conviction score — ADVISORY only
 * (Λ uniqueness = Conjecture 1) — then capped at the 0.97 trust ceiling.
 * If any component is uncomputable the signal abstains (no value).
 */
import { lambdaAggregate, periodReturn, zScore, annualizedVol, hoeffdingConfidence, squash01 } from './formulas.mjs';
import { capTrust, LAMBDA_STATUS } from './canon.mjs';

export const STRATEGIES = Object.freeze({
  tsmom: { id: 'tsmom', kind: 'momentum', label: 'HEURISTIC', lineage: 'time-series momentum (Moskowitz–Ooi–Pedersen 2012), adapted to daily crypto closes' },
  meanrev: { id: 'meanrev', kind: 'mean-reversion', label: 'HEURISTIC', lineage: 'rolling z-score reversion, standard stat-arb shape, adapted' },
});

/**
 * Evaluate one asset's daily-close series at its last observation.
 * Returns a signal intent or an abstention (never an invented value):
 * { action: 'ENTER_LONG'|'EXIT_LONG'|'HOLD'|'ABSTAIN', components, conviction }
 */
export function evaluate(series, params) {
  const closes = series.map((s) => s.close);
  const { momentumLookback, zWindow, zEntry, volWindow } = params;

  const momRet = periodReturn(closes, momentumLookback);
  const z = zScore(closes, zWindow);
  const vol = annualizedVol(closes, volWindow);

  if (momRet === null || z === null || vol === null) {
    return {
      action: 'ABSTAIN',
      note: `insufficient/invalid history for lookbacks (mom=${momentumLookback}, z=${zWindow}, vol=${volWindow}) — abstaining (NOT-MEASURED carries no value)`,
    };
  }

  // Component scores in [0,1] (HEURISTIC transforms, stated):
  // momentum edge squashed by realized-vol scale; reversion depth squashed.
  const momScore = squash01(momRet / Math.max(vol / Math.sqrt(365) * Math.sqrt(momentumLookback), 1e-9), 1);
  const revScore = squash01(-z / Math.max(zEntry, 1e-9), 1);
  // sample-size awareness (Hoeffding SHAPE; iid does not hold ⇒ HEURISTIC)
  const nEff = closes.length - 1;
  const sampleScore = hoeffdingConfidence(nEff, 0.01, -0.5, 0.5) ?? 0;

  const components = {
    momentum: { value: momScore, label: 'HEURISTIC', evidence: { trailingReturn: momRet, lookbackDays: momentumLookback } },
    reversion: { value: revScore, label: 'HEURISTIC', evidence: { zScore: z, windowDays: zWindow } },
    sampleConfidence: { value: sampleScore, label: 'HEURISTIC', evidence: { nObservations: nEff, note: 'Hoeffding shape; iid violated by markets' } },
  };

  // Λ roll-up — ADVISORY only.
  const lam = lambdaAggregate([momScore, revScore, sampleScore]);
  const conviction = lam === null ? null : capTrust(lam);

  let action = 'HOLD';
  if (momRet > 0 && z <= -zEntry) action = 'ENTER_LONG';        // both agree
  else if (momRet > 0 && Math.abs(z) < zEntry) action = 'ENTER_LONG'; // momentum regime, no stretch
  else if (z >= 0 && momRet <= 0) action = 'EXIT_LONG';

  return {
    action,
    components,
    conviction,                              // ∈ [0, 0.97] or null
    lambda: { status: LAMBDA_STATUS, advisory: true },
    params,
  };
}
