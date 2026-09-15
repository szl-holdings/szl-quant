# Paper research qualification — 2026-09-15

This is a dated research observation and source repair, not capital admission.
No book reset, threshold relaxation, key replacement, historical receipt rewrite,
new publisher, wallet, broker order, funded account or geographic bypass is added.

## Actual canonical observation

Source inspected: `0a18eea4c0ced5543e0536bf84b3cb47b88ecc0f`.
Ledger inspected: `7284cbc41479486c9d9de5c663f7c7972cb578b4`.
Both branch tips matched the captured revisions on the collector's readback.
Public acquisition: puriq-live workflow run `34926876971`, artifact `10379328821`,
archive SHA256 `2d24f462f7ff9b78a6bd4c4dfd46b766a4054ae7723879dc91c1172a4b4a191e`.
No acquired code was executed by that collector.

The unmodified repository verifier was then executed locally against the captured
ledger and repository-pinned public keys. Chain, book, refusals, Rekor/inclusion/
consistency, RFC3161 and second-observer gossip checks all returned exit zero.
This is offline verification of captured evidence, not a fresh query to witnesses.
The timestamp anchors are repository-pinned, not an independently resolved WebPKI.
The second observer is the same operator from another vantage point.

- 252 run directories; 2,742 receipt files; 250 chain links.
- 244 simulated book states. Earliest book: 2026-07-16T17:39:07.920Z.
- Latest book: 2026-09-15T01:05:59.377Z, seq244, USD10,000 virtual cash/equity,
  zero open positions and zero simulated fills across all inspected book states.
- 1,502 signal receipts: 596 ALLOWED HOLD, 408 BLOCKED HOLD,
  392 BLOCKED ENTER_LONG, 92 ALLOWED EXIT_LONG, 14 BLOCKED EXIT_LONG.
  There were no ALLOWED ENTER_LONG signals in this captured population.
- Latest signed track record: zero realized +1d and +7d outcomes; both hit rates null.
- Frozen book assumptions remain 30bps fee and 20bps slippage; neither is a
  measured venue-specific execution-cost calibration. The USD1,000 PURIQ replay
  is a different virtual experiment, not this ledger's capital or an allocation.

Integrity passes. Net trading skill and capital eligibility are **NOT ESTABLISHED**.
Abstention is preserved; empty samples and unchanged cash must not become a
profitability badge. Paper duration with no entries is not traded-market experience.

## Reproduced source defect and repair

The previous scoreSignal accepted a +7d future close at an evaluation clock only
+1d after the signal and labeled the future return MEASURED. A two-row synthetic
100-to-200 fixture reproduced this error; this was not a real market gain.

The existing scoring path now filters observations to its explicit as-of clock,
refuses future signal times, rejects malformed/duplicate/unordered histories,
bounds daily baseline and outcome alignment, and rejects nonfinite ratios.
It records the actual evaluated clock, alignment lags and realized interval.
Requested horizons remain decision-clock aligned, not executable holding periods.
A new researchQualification field in the existing buildTrackRecord output exposes
empty populations and preserves HOLD/no-capital/no-live-execution even when some
past descriptive returns are positive. Existing scheduled paper calls use this
same function after normal source admission; the schedule and signing path are unchanged.

Twenty-five new network-free tests cover future perturbation/truncation, invalid
clocks, numeric domains, gaps, horizon configuration and non-authorizing aggregates.
Local Node22.16.0: 139 tests, 138 passed, zero failed, one existing signing-bridge
fixture skip. Native source qualification must be read from the exact candidate
run; this document does not predeclare native or production success.
Historical receipt signatures, frozen book replay and witness code are unchanged.

## What remains unproved

A close timestamp is not a historical publication/availability timestamp. The
as-of repair does not establish dataset vintages, complete venue coverage,
realized slippage, fill probability, out-of-sample model skill, or live eligibility.
The book's symbol-keyed holdings and decision-time DEX snapshot fills also require
separate design review before any future execution-grade simulation is claimed.
Do not loosen gates merely to make the book trade.

## Study, adapt, verify — original SZL research integration

No upstream source is copied by this repair. These primary sources inform research
patterns, not a claim that their reported returns transfer to SZL:

- Freqtrade lookahead analysis: https://www.freqtrade.io/en/stable/lookahead-analysis/
  Adapted here as future-perturbation and prefix-invariance tests. Untouched signal
  branches are not validated just because a test population has no trades.
- QuantConnect/LEAN reality modeling: https://www.quantconnect.com/docs/v2/writing-algorithms/reality-modeling/slippage/key-concepts
  Follow-on requirement: calibrate cost/slippage assumptions and retain stress
  sweeps; existing bps assumptions remain explicitly modeled.
- NautilusTrader backtesting: https://nautilustrader.io/docs/latest/concepts/backtesting/
  Follow-on requirement: event-time replay, venue/instrument identity, latency,
  depth and partial-fill semantics. No Nautilus runtime is installed by this change.
- Microsoft R&D-Agent-Quant: https://arxiv.org/abs/2505.15155
  Follow-on design: separate research hypotheses, code/evaluation and feedback.
  SZL's existing agents propose experiments; deterministic evaluators and receipts
  retain evidence, and no model can grant itself financial authority.
- Alpaca paper limitations: https://docs.alpaca.markets/us/docs/paper-trading
  Paper behavior is not a substitute for measured execution or a profit promise.

The proposed next research loop is hypothesis -> frozen data/time contract ->
independent falsification -> cost/latency stress -> registered forward-paper
observation -> signed evidence and human review. It remains research-only.
