# Finance research adaptation — 2026-09-15

Scope: original software research and the existing paper engine. No funded order, capital transfer, new signed book, model-quality certificate or profitability claim.

## Concurrent-source reconciliation

The initial PR24 implementation reproduced future-outcome leakage at old main `0a18eea4c0ced5543e0536bf84b3cb47b88ecc0f` and passed its own native source tests. While review completed, PR23 admitted a broader temporal repair at `ac0af68521a3ba09e701b519bddc77fbe70769a8`. A normal merge of PR24 was rejected with a conflict; no source was overwritten or bypassed.

This successor preserves the complete admitted PR23 tree, its strict history ordering and bounds, horizon validation, reason codes, temporal diagnostics, researchQualification HOLD, all 139 existing tests, paper qualification document and existing complete CI. It adds only explicit publication-availability enforcement, eight focused regressions, a pinned runner hardener and this prior-art/integration note. It does not restore the initial PR24 sorting behavior or replace the now-admitted scorer.

When an observation supplies `availableAtMs`, that timestamp must be valid and no earlier than its event timestamp. An event completed before the evaluation clock cannot become a measured result while its stated publication availability is still in the future. Missing availability preserves legacy event-time semantics; it never manufactures verified point-in-time vintages. Invalid histories are not silently repaired. Original receipts and the canonical book remain unchanged.

The initial 135-case PR24 run is historical evidence for its original source only. The reconciled suite has 147 discovered cases, including the 139 admitted predecessor cases and eight availability cases. The existing environment-dependent signing-handoff skip remains a skip, not a pass. Inspect exact-head and subsequent main native evidence; do not transfer the old run's PASS to new source.

## Primary systems studied and SZL adaptation

These are engineering references, not a ranking of demonstrated profitability. No third-party implementation is copied into this repair.

| Reference | Pattern worth studying | Existing SZL destination |
|---|---|---|
| QuantConnect LEAN | Separate signal, portfolio and risk concerns; explicit fill, fee, slippage, buying-power and settlement models | Keep A11oy proposals separate from deterministic szl-quant accounting and Hatun review. Cost scenarios and equally budgeted baselines are research requirements, not execution guarantees. |
| NautilusTrader | Persist events and reconcile external state; distinguish missing/incomplete evidence from flat or confirmed state | Keep signed-book identity and receipts; never infer zero holdings or success from an unavailable observation. No live venue adapter is added here. |
| Microsoft Qlib and RD-Agent | Reproducible datasets, point-in-time handling, model experiments and research pipelines | Bind dataset/model/code/prompt revisions, retain attempted experiments and keep held-out windows outside tuning. This remains proposed integration, not a trained financial model. |
| Freqtrade lookahead analysis | Expose future-data dependencies by restricting what each evaluation can observe | The SZL temporal and publication-availability regressions test the analogous boundary in the existing scorer. |
| TauricResearch TradingAgents | Separate analyst roles and adversarial debate | Existing A11oy agents can produce structured theses and counter-theses; agreement among agents is not independent evidence or financial authorization. |
| Alpaca paper-trading documentation | Preserve the distinction between simulation and actual market fills | Qualify paper behavior separately; do not infer liquidity, queue priority, latency or profitable live execution from a simulation. |

Primary references consulted on 2026-09-15:
- https://www.quantconnect.com/docs/v2/writing-algorithms/algorithm-framework/risk-management/key-concepts
- https://www.quantconnect.com/docs/v2/writing-algorithms/reality-modeling/key-concepts
- https://nautilustrader.io/docs/latest/concepts/execution/reconciliation/
- https://github.com/microsoft/qlib
- https://github.com/TauricResearch/TradingAgents
- https://www.freqtrade.io/en/stable/lookahead-analysis/
- https://docs.alpaca.markets/us/docs/paper-trading

Inspect licenses, exact versions, notices and data rights before integrating any implementation. Studying a pattern does not transfer branding rights or license an entire ecosystem. Vela's attributed chart component in PURIQ does not license PineTS under the same terms.

## One finance release, not competing products

PURIQ research source was admitted through PR16 at `91717976275b685bef5f6ba9caa40b43fc1efff5`; main run34926967026 passed. Its $1,000 display is a stateless virtual baseline, not the existing $10,000 canonical book.

Preserve concurrent A11oy PR2176's 16-source finance backend and existing `SZLHOLDINGS/finance` projection. Do not replace it with the standalone research application's smaller source set, add an independent writer or create another Space. The joint release needs both canonical A11oy identity and the admitted PURIQ component identity, actual mounted research routes, same-origin chart bytes and attribution, anonymous public probes, exact-HF readback and the native publisher receipt.

The shared public-smoke repair `.github#743` still requires ordinary protected merge-queue admission before its consumer pins can be adopted. No current component test completes that dependency or the final deployment.

## Research-agent contract

PURIQ adapters produce typed, timestamped observations with source identities, units, completeness and provenance. Existing A11oy research agents may propose hypotheses and falsification tests; source text is untrusted data and cannot grant tool permissions. Deterministic gates and Hatun review remain separate from models. The canonical szl-quant book evaluates paper scenarios with visible costs, held-out windows and all attempted/rejected candidates. Receipts distinguish observations, modeled results, unavailable evidence and verified deployment.

Still unproven: historical publication vintages and data rights, financial model skill, out-of-sample and forward performance, actual cost calibration, sufficient observations and benchmark-relative results. Zero exposure is not evidence of a safe or profitable strategy. No transition to unattended real-money authority is implemented.
