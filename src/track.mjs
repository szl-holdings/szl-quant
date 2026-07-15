/**
 * track.mjs — the VERIFIABLE TRACK RECORD: score past advisory signals
 * against what the market actually did next, from VERIFIED receipts only.
 *
 * This is the anti-"calls account". X calls accounts post hindsight-edited
 * wins; szl-quant's scoreboard is computed exclusively from DSSE-verified
 * signal receipts (tampered/unsigned files are EXCLUDED and listed), over
 * the FULL population (every signal ever emitted — BLOCKED no-calls
 * included as rows), and the resulting report is itself DSSE-signed.
 *
 * Honesty rules (binding):
 *   - Realized forward returns are MEASURED from real daily closes, with
 *     baseline AND outcome taken from ONE source series (no cross-venue
 *     return math; the DEX snapshot price is echoed as REPORTED context
 *     only, never used in the return calculation).
 *   - A horizon that has not elapsed yet is UNAVAILABLE ("pending", with
 *     the date it becomes measurable) — never a guess, never dropped.
 *   - Hit-rate is a measured frequency of the past, NOT a probability
 *     estimate; small samples carry an in-band weak-evidence note.
 *   - BLOCKED signals are never scored (no position was advised) but are
 *     counted and tallied — abstaining in bad conditions is part of the
 *     record, not something to hide.
 */

const DAY_MS = 86_400_000;
export const HORIZONS_DAYS = Object.freeze([1, 7]);
export const WEAK_EVIDENCE_N = 10;

/** Decision time of a signal receipt: ISO suffix of the subject name
 *  (decision clock), falling back to the snapshot observation time. */
export function signalTimeMs(statement) {
  const name = statement?.subject?.[0]?.name ?? '';
  const iso = name.split('/').pop();
  const t = Date.parse(iso);
  if (Number.isFinite(t)) return t;
  const snap = statement?.predicate?.decision?.snapshot?.observedAtIso;
  const t2 = Date.parse(snap ?? '');
  return Number.isFinite(t2) ? t2 : null;
}

/**
 * Verify DSSE envelopes against the PINNED engine pubkey. Input entries:
 * [{ file, envelope }]. Returns { verified: [{file, statement}], excluded:
 * [{file, fails}] }. Only cryptographically verified statements may enter
 * the track record — an unverifiable receipt is a fact we do NOT have.
 */
export function verifySignalEnvelopes(entries, publicKey, { verifyEnvelope }) {
  const verified = [];
  const excluded = [];
  for (const { file, envelope } of entries) {
    let v;
    try { v = verifyEnvelope(envelope, publicKey); } catch (e) { v = { ok: false, fails: [String(e?.message ?? e)] }; }
    if (v.ok) verified.push({ file, statement: v.payload });
    else excluded.push({ file, fails: v.fails ?? ['verification failed'] });
  }
  return { verified, excluded };
}

/**
 * Score one signal against a daily close series (same-source baseline and
 * outcome). Pure. Returns per-horizon outcomes keyed `h${days}d`.
 */
export function scoreSignal({ statement, series, source, nowMs, horizons = HORIZONS_DAYS }) {
  const t0 = signalTimeMs(statement);
  const out = {};
  if (t0 === null) {
    for (const h of horizons) out[`h${h}d`] = { label: 'UNAVAILABLE', note: 'signal time unparseable — cannot score honestly' };
    return { t0: null, outcomes: out };
  }
  const closes = Array.isArray(series) ? series : [];
  const baseline = closes.find((c) => c.tMs >= t0) ?? null;
  for (const h of horizons) {
    const dueMs = t0 + h * DAY_MS;
    if (!baseline) {
      // No close at/after signal time: either the series ended (gap) or the
      // first post-signal close has not printed yet (pending).
      if (nowMs < t0 + DAY_MS) {
        out[`h${h}d`] = { label: 'UNAVAILABLE', note: `pending — first measurable close ~${new Date(t0 + DAY_MS).toISOString().slice(0, 10)}`, pendingUntilIso: new Date(dueMs + DAY_MS).toISOString() };
      } else {
        out[`h${h}d`] = { label: 'UNAVAILABLE', note: 'history gap: no close at/after signal time although it has elapsed' };
      }
      continue;
    }
    const outcome = closes.find((c) => c.tMs >= dueMs) ?? null;
    if (outcome) {
      out[`h${h}d`] = {
        label: 'MEASURED',
        forwardReturn: outcome.close / baseline.close - 1,
        baselineIso: new Date(baseline.tMs).toISOString(),
        outcomeIso: new Date(outcome.tMs).toISOString(),
        source: source ?? 'unknown',
      };
    } else if (nowMs < dueMs + DAY_MS) {
      out[`h${h}d`] = { label: 'UNAVAILABLE', note: `pending — horizon elapses ~${new Date(dueMs).toISOString().slice(0, 10)}`, pendingUntilIso: new Date(dueMs + DAY_MS).toISOString() };
    } else {
      out[`h${h}d`] = { label: 'UNAVAILABLE', note: 'history gap: horizon elapsed but no close available in series' };
    }
  }
  return { t0, outcomes: out };
}

function median(xs) {
  const s = [...xs].sort((a, b) => a - b);
  const n = s.length;
  if (n === 0) return null;
  return n % 2 ? s[(n - 1) / 2] : (s[n / 2 - 1] + s[n / 2]) / 2;
}

/**
 * Build the full track-record report. `histories` maps asset address →
 * { ok, series, dataset } | { ok:false, unavailable } (resilient-ingest
 * contract). FULL population: every verified signal becomes a row.
 */
export function buildTrackRecord({ verified, excluded, histories, nowMs, horizons = HORIZONS_DAYS }) {
  const rows = [];
  const blockedGateTally = new Map();
  let blocked = 0;
  let scoredRows = 0;

  for (const { file, statement } of verified) {
    const d = statement?.predicate?.decision ?? {};
    const addr = d.asset?.address;
    const scoreable = d.verdict === 'ALLOWED' && d.proposedAction === 'ENTER_LONG';
    const row = {
      file,
      symbol: d.asset?.symbol ?? 'unknown',
      signalIso: (() => { const t = signalTimeMs(statement); return t === null ? null : new Date(t).toISOString(); })(),
      verdict: d.verdict ?? 'unknown',
      proposedAction: d.proposedAction ?? null,
      conviction: d.conviction ?? null,
      snapshotPriceUsd: d.snapshot?.priceUsd ?? null, // REPORTED context only — NOT used in return math
      scored: scoreable,
    };
    if (d.verdict === 'BLOCKED') {
      blocked += 1;
      for (const g of d.blockedBy ?? []) blockedGateTally.set(g, (blockedGateTally.get(g) ?? 0) + 1);
      row.note = 'no-call (BLOCKED) — never scored, honestly counted';
    }
    if (scoreable) {
      scoredRows += 1;
      const hist = histories?.[addr];
      if (hist?.ok) {
        const { outcomes } = scoreSignal({ statement, series: hist.series, source: hist.dataset?.source, nowMs, horizons });
        row.outcomes = outcomes;
        row.seriesSha256 = hist.dataset?.sha256 ?? null;
      } else {
        row.outcomes = Object.fromEntries(horizons.map((h) => [`h${h}d`, { label: 'UNAVAILABLE', note: hist?.unavailable?.note ?? 'history unavailable for asset — cannot measure' }]));
      }
    }
    rows.push(row);
  }

  const aggregates = {};
  for (const h of horizons) {
    const realized = rows
      .filter((r) => r.scored && r.outcomes?.[`h${h}d`]?.label === 'MEASURED')
      .map((r) => r.outcomes[`h${h}d`].forwardReturn);
    const pending = rows.filter((r) => r.scored && /pending/.test(r.outcomes?.[`h${h}d`]?.note ?? '')).length;
    const gaps = rows.filter((r) => r.scored && r.outcomes?.[`h${h}d`]?.label === 'UNAVAILABLE' && !/pending/.test(r.outcomes?.[`h${h}d`]?.note ?? '')).length;
    const n = realized.length;
    const wins = realized.filter((x) => x > 0).length;
    aggregates[`h${h}d`] = {
      label: 'MEASURED',
      nRealized: n,
      nPending: pending,
      nGaps: gaps,
      wins,
      hitRate: n > 0 ? wins / n : null,
      meanForwardReturn: n > 0 ? realized.reduce((a, b) => a + b, 0) / n : null,
      medianForwardReturn: median(realized),
      note: n === 0
        ? 'no realized outcomes yet — hit-rate honestly null (nothing to measure)'
        : n < WEAK_EVIDENCE_N
          ? `weak evidence (n=${n} < ${WEAK_EVIDENCE_N}) — a measured frequency of the past, NOT a probability estimate`
          : 'measured frequency of the past, NOT a probability estimate',
    };
  }

  return {
    generatedAtIso: new Date(nowMs).toISOString(),
    horizonsDays: [...horizons],
    inputs: {
      signalReceipts: verified.length + excluded.length,
      verified: verified.length,
      excluded, // full list with reasons — unverifiable receipts are named, not hidden
    },
    population: {
      total: rows.length,
      scored: scoredRows,
      blocked,
      // Array-of-objects shape ON PURPOSE: gate names as raw keys would
      // collide with the verifier's trust-ceiling scan for `conviction`
      // fields (a count of 2 must never look like a conviction of 2).
      noCallsByGate: [...blockedGateTally.entries()].sort((a, b) => a[0].localeCompare(b[0])).map(([gate, count]) => ({ gate, count })),
      note: 'FULL population — every verified signal is a row; BLOCKED no-calls counted, never scored, never hidden',
    },
    aggregates,
    signals: rows,
    honesty: 'MEASURED values describe realized past forward returns of ADVISORY paper signals (baseline and outcome from ONE source series). They predict nothing. Not financial advice.',
  };
}
