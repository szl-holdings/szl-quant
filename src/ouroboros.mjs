/**
 * ouroboros.mjs — loop-tax accounting for the engine's feedback loop,
 * adapted from szl-holdings/ouroboros `runLoop` (bounded recursion with a
 * governance budget; the trace is the product).
 *
 * Semantics kept from the kernel:
 *  - the loop MUST terminate on budget (maxSteps fail-closed to default
 *    if non-finite — an unbounded loop defeats the primitive);
 *  - exit reasons: converged | consistent | aborted | budgetExhausted;
 *  - a typed trace of every step is emitted, receipts downstream.
 *
 * Added here: the LOOP TAX. Every iteration of the engine's
 * observe→signal→gate→account cycle charges `taxPerStep` against a
 * governance budget. When the ledger is exhausted the loop-tax gate BLOCKS
 * further signal emission (honest BLOCKED verdict), so the engine cannot
 * spin unbounded feedback on itself. The ledger is part of the receipt.
 */

const DEFAULT_MAX_STEPS = 8;

export function makeLoopTaxLedger({ budget = DEFAULT_MAX_STEPS, taxPerStep = 1 } = {}) {
  const b = Number.isFinite(budget) ? Math.max(0, Math.floor(budget)) : DEFAULT_MAX_STEPS;
  return { budget: b, taxPerStep, spent: 0, remaining: b, charges: [] };
}

/** Charge one loop iteration to the ledger. Returns the charge record. */
export function chargeLoopTax(ledger, label, meta = {}) {
  const charge = {
    index: ledger.charges.length,
    label,
    tax: ledger.taxPerStep,
    atMs: meta.atMs ?? null,
    ...meta,
  };
  ledger.spent += ledger.taxPerStep;
  ledger.remaining = Math.max(0, ledger.budget - ledger.spent);
  ledger.charges.push(charge);
  return charge;
}

/**
 * Run a bounded engine loop (ouroboros shape). Caller supplies:
 *   initialState, step(state, i) → { state, output?, abort? },
 *   delta(prev, next) → number (magnitude of change).
 * Exits: converged (delta ≤ convergenceThreshold), aborted, budgetExhausted.
 * Every step charges loop tax. Returns { trace, ledger }.
 */
export function runBoundedLoop({ initialState, step, delta, config = {} }) {
  const rawMax = config.maxSteps ?? DEFAULT_MAX_STEPS;
  const maxSteps = Number.isFinite(rawMax) ? Math.max(0, Math.floor(rawMax)) : DEFAULT_MAX_STEPS;
  const convergenceThreshold = config.convergenceThreshold ?? 1e-3;
  const label = config.label ?? 'szl-quant.cycle';
  const ledger = config.ledger ?? makeLoopTaxLedger({ budget: maxSteps, taxPerStep: config.taxPerStep ?? 1 });

  const steps = [];
  let state = initialState;
  let exitReason = 'budgetExhausted';
  const startedAt = Date.now();

  for (let i = 0; i < maxSteps; i++) {
    if (ledger.remaining <= 0) { exitReason = 'budgetExhausted'; break; }
    const t0 = Date.now();
    const res = step(state, i);
    chargeLoopTax(ledger, `${label}#${i}`, { atMs: t0 });
    const d = i === 0 ? 0 : Math.abs(delta(state, res.state));
    steps.push({ index: i, deltaMagnitude: d, durationMs: Date.now() - t0, output: res.output ?? null });
    state = res.state;
    if (res.abort) { exitReason = 'aborted'; break; }
    if (i > 0 && d <= convergenceThreshold) { exitReason = 'converged'; break; }
  }

  return {
    trace: {
      id: `loop_${startedAt.toString(36)}_${steps.length}`,
      label,
      steps,
      finalState: state,
      exitReason,
      stepsRun: steps.length,
      maxSteps,
      totalDurationMs: Date.now() - startedAt,
    },
    ledger,
  };
}
