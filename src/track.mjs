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
  const iso = typeof name === 'string' ? name.split('/').pop() : '';
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
  if (!Array.isArray(horizons) || horizons.length === 0 || horizons.length > 32
      || new Set(horizons).size !== horizons.length
      || !horizons.every((h) => Number.isSafeInteger(h) && h > 0 && h <= 3650)) {
    throw new TypeError('horizons must be unique positive integer days, bounded to 3650');
  }
  const t0 = signalTimeMs(statement);
  const out = {};
  const unavailable = (code, note) => {
    for (const h of horizons) out[`h${h}d`] = { label: 'UNAVAILABLE', code, note };
    return { t0, outcomes: out };
  };
  // Explicit evaluation clock: a later row in a supplied history cannot make
  // an unelapsed outcome measurable. Milliseconds must remain Date-safe.
  const validClock = (t) => Number.isSafeInteger(t) && t >= 0 && t <= 8.63e15;
  if (!validClock(nowMs)) return unavailable('INVALID_AS_OF', 'evaluation clock invalid — cannot score honestly');
  if (!validClock(t0)) return unavailable('INVALID_SIGNAL_TIME', 'signal time unparseable — cannot score honestly');
  if (t0 > nowMs) return unavailable('FUTURE_SIGNAL', 'signal is later than the evaluation clock — not yet observable');
  if (!Array.isArray(series) || series.length > 100_000) {
    return unavailable('INVALID_HISTORY', 'history must be a bounded array of daily closes');
  }
  // Do not silently sort, coerce, deduplicate, interpolate or repair prices.
  // An invalid series is not an empty, zero-return or winning observation.
  let previous = -1;
  for (const c of series) {
    if (!c || !validClock(c.tMs) || c.tMs <= previous
        || typeof c.close !== 'number' || !Number.isFinite(c.close) || c.close <= 0) {
      return unavailable('INVALID_HISTORY', 'history must contain strictly increasing timestamps and finite positive prices');
    }
    if (Object.hasOwn(c, 'availableAtMs')
        && (!validClock(c.availableAtMs) || c.availableAtMs < c.tMs)) {
      return unavailable('INVALID_AVAILABILITY', 'publication availability must be Date-safe and not precede event time');
    }
    previous = c.tMs;
  }
  // Event time and publication availability are different clocks. Honor the
  // latter when supplied; never infer a verified vintage from its absence.
  const closes = series.filter((c) => c.tMs <= nowMs
    && (!Object.hasOwn(c, 'availableAtMs') || c.availableAtMs <= nowMs));
  const baseline = closes.find((c) => c.tMs >= t0 && c.tMs < t0 + DAY_MS) ?? null;
  for (const h of horizons) {
    const dueMs = t0 + h * DAY_MS;
    if (!baseline) {
      out[`h${h}d`] = nowMs < t0 + DAY_MS
        ? { label: 'UNAVAILABLE', code: 'BASELINE_PENDING', note: 'pending — first completed daily baseline not yet observed', pendingUntilIso: new Date(t0 + DAY_MS).toISOString() }
        : { label: 'UNAVAILABLE', code: 'BASELINE_GAP', note: 'history gap: no daily baseline within one day after the signal' };
      continue;
    }
    if (nowMs < dueMs) {
      out[`h${h}d`] = { label: 'UNAVAILABLE', code: 'HORIZON_PENDING', note: 'pending — requested horizon has not elapsed at the evaluation clock', pendingUntilIso: new Date(dueMs).toISOString() };
      continue;
    }
    // Decision-clock horizons retain the existing contract, with bounded
    // daily alignment. Never reuse a late baseline as its own outcome.
    const outcome = closes.find((c) => c.tMs >= dueMs && c.tMs < dueMs + DAY_MS && c.tMs > baseline.tMs) ?? null;
    if (outcome) {
      const forwardReturn = outcome.close / baseline.close - 1;
      if (!Number.isFinite(forwardReturn)) {
        out[`h${h}d`] = { label: 'UNAVAILABLE', code: 'NONFINITE_RETURN', note: 'price ratio exceeds finite numeric range — result withheld' };
        continue;
      }
      out[`h${h}d`] = {
        label: 'MEASURED', forwardReturn,
        baselineIso: new Date(baseline.tMs).toISOString(),
        outcomeIso: new Date(outcome.tMs).toISOString(),
        evaluatedAsOfIso: new Date(nowMs).toISOString(),
        horizonAnchor: 'decision-clock',
        baselineLagMs: baseline.tMs - t0,
        outcomeLagMs: outcome.tMs - dueMs,
        realizedIntervalMs: outcome.tMs - baseline.tMs,
        source: source ?? 'unknown',
      };
    } else if (nowMs < dueMs + DAY_MS) {
      out[`h${h}d`] = { label: 'UNAVAILABLE', code: 'OUTCOME_PENDING', note: 'pending — completed daily outcome not yet observed', pendingUntilIso: new Date(dueMs + DAY_MS).toISOString() };
    } else {
      out[`h${h}d`] = { label: 'UNAVAILABLE', code: 'OUTCOME_GAP', note: 'history gap: no daily outcome in the requested horizon window' };
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
    researchQualification: {
      schema: 'szl.quant.track-qualification/v1',
      state: 'HOLD',
      temporalContract: 'decision-clock-asof/v2',
      evidenceState: rows.length === 0 ? 'NO_VERIFIED_SIGNALS'
        : scoredRows === 0 ? 'NO_ENTRY_SIGNALS'
          : Object.values(aggregates).every((a) => a.nRealized === 0)
            ? 'NO_REALIZED_OUTCOMES' : 'DESCRIPTIVE_OUTCOMES_ONLY',
      horizonCounts: Object.fromEntries(Object.entries(aggregates).map(([h, a]) =>
        [h, { realized: a.nRealized, pending: a.nPending, gaps: a.nGaps }])),
      pointInTimeVintagesVerified: false,
      executionCostCalibrationVerified: false,
      outOfSampleSkillEstablished: false,
      capitalAdmission: false,
      liveExecution: false,
      note: 'Signatures and descriptive outcomes do not establish net trading skill. Missing or empty outcome evidence cannot authorize capital. Horizon samples may overlap and are not independent trials.',
    },
    signals: rows,
    honesty: 'MEASURED values describe realized past forward returns of ADVISORY paper signals (baseline and outcome from ONE source series). They predict nothing. Not financial advice.',
  };
}
