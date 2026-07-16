// Refusal record — the engine's "no" is a decision, not an absence.
//
// Every run dir gets a signed census of its decisions: what was proposed,
// what was ALLOWED, what was BLOCKED, and BY WHICH GATE. The point is
// doctrine, not decoration: a record dominated by refusals must explain
// itself on the ledger, in a receipt an independent verifier can REPLAY
// from the DSSE-verified decision receipts alone.
//
// Pure functions only — the CLI wires IO, the verifier mirrors these rules
// independently (zero imports from here).

export const REFUSALS_FILE_RE = /^refusals_\d+\.receipt\.json$/;

/** Extract exactly the fields the census counts; null on shape miss. */
export function decisionForRefusals(file, statement) {
  const dec = statement?.predicate?.decision;
  if (!dec?.asset?.symbol || !dec.proposedAction || !dec.verdict) return null;
  return {
    file,
    symbol: dec.asset.symbol,
    verdict: dec.verdict,
    proposedAction: dec.proposedAction,
    conviction: typeof dec.conviction === 'number' ? dec.conviction : null,
    blockedBy: Array.isArray(dec.blockedBy) ? [...dec.blockedBy].sort() : [],
  };
}

/** Deterministic census body for one run dir. */
export function buildRefusalsBody({ decisions, runDir, nowIso, excludedSignals }) {
  const sorted = [...decisions].sort((a, b) => (a.symbol < b.symbol ? -1 : a.symbol > b.symbol ? 1 : 0));
  const byAction = {};
  const gateCounts = {};
  let allowed = 0;
  let blocked = 0;
  for (const d of sorted) {
    byAction[d.proposedAction] = (byAction[d.proposedAction] ?? 0) + 1;
    if (d.verdict === 'ALLOWED') allowed++;
    else blocked++; // any non-ALLOWED verdict counts as a refusal — honest catch-all
    for (const g of d.blockedBy) gateCounts[g] = (gateCounts[g] ?? 0) + 1;
  }
  // Array-of-{gate,count} on purpose: gate names (e.g. "conviction") must
  // never become object keys holding numbers, or an honest COUNT would look
  // like a trust value to the doctrine ceiling scanner. Sorted by gate name.
  const refusalsByGate = Object.entries(gateCounts).sort(([a], [b]) => (a < b ? -1 : 1)).map(([gate, count]) => ({ gate, count }));
  return {
    kind: 'szl-quant-refusals',
    runDir,
    generatedAtIso: nowIso,
    inputs: {
      signalFiles: sorted.map((d) => d.file).sort(),
      excludedSignals: excludedSignals ?? { count: 0, files: [] },
    },
    decisions: sorted,
    totals: { decisions: sorted.length, allowed, blocked, byAction, refusalsByGate },
    labels: {
      counts: 'MEASURED',
      convictions: 'HEURISTIC',
      note: 'counts are MEASURED over the DSSE-verified decision receipts in this run dir alone; convictions are echoed HEURISTIC values (ceiling-capped upstream, never proven trust)',
    },
    note: 'refusals are part of the record — a BLOCKED verdict is a decision, not an absence; this receipt makes the reasons countable',
    limits: [
      'per-run census only — cross-run aggregation is display-level and must be recomputed from these receipts',
      'says WHY entries were refused, not whether refusing was right — no performance claim',
    ],
  };
}
