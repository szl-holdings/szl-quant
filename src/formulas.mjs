/**
 * formulas.mjs — the strategy layer's mathematical vocabulary, expressed
 * through the SZL formula canon's shapes (szl-formulas kernel conventions).
 *
 * PROOF HONESTY (binding):
 *  - Λ (lambdaAggregate) is the D2 weighted geometric mean. Λ uniqueness is
 *    Conjecture 1 (OPEN). Every Λ roll-up here is ADVISORY — never proven trust.
 *  - Per-function `proofNote` states exactly what IS established (obligation-
 *    level, e.g. an inequality's textbook status) — it is NOT a claim of
 *    membership in the locked-proven canonical set {F1,F4,F7,F11,F12,F18,F19,F22},
 *    whose mapping onto these implementations is NOT asserted (UNKNOWN).
 *  - Market-facing use of any bound is HEURISTIC: iid/bounded assumptions do
 *    not hold for market returns. Labels say so.
 */
import { capTrust } from './canon.mjs';

/**
 * Λ aggregate — weighted geometric mean of scores in [0,1] (canon D2 shape).
 * Returns null (no value) if inputs are empty/invalid — never invents.
 * ADVISORY only (Conjecture 1).
 */
export function lambdaAggregate(scores, weights = null) {
  if (!Array.isArray(scores) || scores.length === 0) return null;
  const w = weights ?? scores.map(() => 1 / scores.length);
  if (w.length !== scores.length) return null;
  const wSum = w.reduce((a, b) => a + b, 0);
  if (!(wSum > 0)) return null;
  let logSum = 0;
  for (let i = 0; i < scores.length; i++) {
    const s = scores[i];
    if (!Number.isFinite(s) || s < 0 || s > 1) return null;
    if (s === 0) return 0; // geometric mean: any zero → zero
    logSum += (w[i] / wSum) * Math.log(s);
  }
  return Math.exp(logSum);
}
lambdaAggregate.proofNote = 'weighted geometric mean, homogeneity/boundedness elementary (A2/A4 shapes); Λ uniqueness = Conjecture 1 (OPEN); ADVISORY only';

/** Bounds check (A4 shape): true iff x ∈ [0,1]. */
export function lambdaBounded(x) {
  return Number.isFinite(x) && x >= 0 && x <= 1;
}
lambdaBounded.proofNote = 'interval membership check; elementary';

/**
 * Hoeffding tail bound: P(mean - E[mean] >= t) <= exp(-2 n t² / (b-a)²)
 * for iid samples bounded in [a,b]. Used to turn (n, observed edge) into a
 * sample-size-aware confidence score = 1 - bound, then trust-capped.
 * Market returns are neither iid nor bounded ⇒ label HEURISTIC downstream.
 */
export function hoeffdingConfidence(n, t, a, b) {
  if (!Number.isFinite(n) || n <= 0 || !Number.isFinite(t) || t <= 0) return null;
  const range = b - a;
  if (!(range > 0)) return null;
  const bound = Math.exp((-2 * n * t * t) / (range * range));
  return capTrust(1 - bound);
}
hoeffdingConfidence.proofNote = 'Hoeffding (1963) inequality is textbook-proven for iid bounded variables; its application to market returns violates iid/boundedness ⇒ HEURISTIC';

/** Rolling simple return over lookback periods. */
export function periodReturn(closes, lookback) {
  if (!Array.isArray(closes) || closes.length < lookback + 1) return null;
  const now = closes[closes.length - 1];
  const then = closes[closes.length - 1 - lookback];
  if (!(then > 0) || !Number.isFinite(now)) return null;
  return now / then - 1;
}

/** Mean and (population) std of an array; null if insufficient. */
export function meanStd(xs) {
  if (!Array.isArray(xs) || xs.length < 2) return null;
  const m = xs.reduce((a, b) => a + b, 0) / xs.length;
  const v = xs.reduce((a, b) => a + (b - m) * (b - m), 0) / xs.length;
  return { mean: m, std: Math.sqrt(v) };
}

/** Z-score of the latest close vs a rolling window. */
export function zScore(closes, window) {
  if (!Array.isArray(closes) || closes.length < window + 1) return null;
  const win = closes.slice(-window - 1, -1);
  const ms = meanStd(win);
  if (!ms || !(ms.std > 0)) return null;
  return (closes[closes.length - 1] - ms.mean) / ms.std;
}

/** Daily log returns. */
export function logReturns(closes) {
  const out = [];
  for (let i = 1; i < closes.length; i++) {
    if (!(closes[i - 1] > 0) || !(closes[i] > 0)) return null;
    out.push(Math.log(closes[i] / closes[i - 1]));
  }
  return out;
}

/** Annualized volatility from daily closes (365d crypto convention). */
export function annualizedVol(closes, window) {
  const rets = logReturns(closes.slice(-(window + 1)));
  if (!rets || rets.length < 2) return null;
  const ms = meanStd(rets);
  if (!ms) return null;
  return ms.std * Math.sqrt(365);
}

/** Squash a signed edge into [0,1] via logistic; k controls steepness. */
export function squash01(x, k = 1) {
  if (!Number.isFinite(x)) return null;
  return 1 / (1 + Math.exp(-k * x));
}
