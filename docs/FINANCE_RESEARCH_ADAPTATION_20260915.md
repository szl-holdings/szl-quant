# Finance research adaptation — 2026-09-15

Scope: software research and the existing paper engine. No real-money execution, capital transfer, new signed book, model-quality certification, or profitability claim.

## Implemented repair

At source `0a18eea4c0ced5543e0536bf84b3cb47b88ecc0f`, `scoreSignal` selected an outcome from the supplied series before enforcing the scoring clock. A synthetic fixture with a January 1 baseline, a January 8 endpoint and a January 2 as-of clock returned a seven-day `MEASURED` return. This is a reproducible source defect, not evidence that a historical published result was affected.

The repair filters future event-time rows, honors explicit `availableAtMs` when supplied, rejects invalid visible numbers and duplicate timestamps, sorts a copied view without modifying inputs, and requires the baseline and horizon endpoints to fall within their respective daily sampling windows. Missing daily observations remain unavailable rather than being substituted by a later observation. Pending outcomes remain in the full population, not disguised as wins or silently discarded.

This is an event-time/availability boundary. It does NOT prove that legacy datasets contain point-in-time publication vintages, eliminate every possible training leak, or qualify an investment strategy. Existing signed history is not rewritten. All 114 previously discovered test cases remain in the package suite; 21 new cases are added. One existing environment-dependent signing-handoff test can remain explicitly skipped when its required environment is absent; that skip is not a pass.

## Primary systems studied; original SZL adaptation

These are engineering reference systems, not a ranking of demonstrated profitability. No implementation from the following projects is copied into this repair.

| Primary reference | Useful design pattern | SZL integration target and qualification requirement |
|---|---|---|
| QuantConnect LEAN risk management and reality modeling | Separate signal/portfolio/risk concerns; explicit fill, fee, slippage, buying-power and settlement models | Keep `szl-quant` accounting and policy gates separate from A11oy model proposals. Evaluate fees, slippage, inference/data costs and an equally budgeted baseline; simplified paper fills are not executable quotes. |
| NautilusTrader execution reconciliation | Persistent events, explicit incomplete histories and unknown outcomes, reconciliation instead of assuming missing means flat | Retain signed book identity and receipts; an unavailable or incomplete observation must not imply zero holdings or successful execution. No live venue adapter is introduced here. |
| Microsoft Qlib / RD-Agent | Reproducible datasets, research workflows, model experiments and point-in-time data handling | Bind model/dataset/code revisions, preregister evaluation windows, retain the full attempted experiment population, and prevent tuning on the held-out window. This remains a proposed extension, not a trained financial model. |
| Freqtrade lookahead analysis | Compare results under constrained future information to reveal hindsight dependence | The new regression suite directly tests future-row exclusion and future-price perturbation invariance in the existing SZL scorer. |
| TauricResearch TradingAgents | Separate analyst roles and adversarial debate | Proposed A11oy research roles produce structured evidence-backed hypotheses; Hatun and deterministic controls remain separate. Multiple agents agreeing is not independent evidence or authorization. |
| Alpaca paper-trading documentation | Distinguish simulation from live fills and account behavior | Paper-only evaluation remains separate from funded capital. No broker connection or real-money order is created by this change. |

References consulted on 2026-09-15:
- https://www.quantconnect.com/docs/v2/writing-algorithms/algorithm-framework/risk-management/key-concepts
- https://www.quantconnect.com/docs/v2/writing-algorithms/reality-modeling/key-concepts
- https://nautilustrader.io/docs/latest/concepts/execution/reconciliation/
- https://github.com/microsoft/qlib
- https://github.com/TauricResearch/TradingAgents
- https://www.freqtrade.io/en/stable/lookahead-analysis/
- https://docs.alpaca.markets/us/docs/paper-trading

Inspect the license, exact revision, notices, data rights and dependency closure before adopting any third-party implementation. Studying a pattern does not transfer branding rights or license an entire ecosystem. Vela charting is separately pinned and attributed in the admitted PURIQ application; that does not license PineTS under the same terms.

## Reconcile the existing finance work; do not replace it

PURIQ research source was admitted in `szl-holdings/puriq-live` PR16 at `91717976275b685bef5f6ba9caa40b43fc1efff5`. Main run `34926967026` completed successfully. Its `$1,000` display is a stateless virtual baseline, not the canonical book.

Concurrent `szl-holdings/a11oy` PR2176 implements the finance source adapters and the existing `SZLHOLDINGS/finance` public projection. Preserve that work. The canonical source/publication owner remains A11oy; do not create a competing finance Space or silently replace the multi-source backend with the standalone research application's smaller source set.

The joint release must bind both the canonical A11oy source and any admitted PURIQ research component revision, verify its actual mounted research routes and source-owned chart bytes, keep the public projection anonymous and read-only, and retain the native publication receipt. Do not claim this joint release is complete from either component's tests alone.

The shared public-smoke controller repair `.github#743` is not admitted merely because its feature tests pass. Its normal protected merge-queue admission and the canonical consumer-pin update remain distinct requirements. Do not bypass the queue or send Hub management credentials to public application probes.

## Research-agent contract to build on the existing software

1. PURIQ adapters produce typed observations: provider, instrument/event identity, units, source/event/publication/retrieval times, raw/normalized digests, completeness and access rights.
2. Existing A11oy research agents may propose a thesis, counter-thesis and falsification test with those observation references. Keep news and repository content untrusted; text cannot alter tool permissions or expose secrets.
3. Deterministic gates reject stale/missing evidence, invalid identities, excessive costs and unsupported actions. Hatun review is not an autonomous financial authorization.
4. `szl-quant` evaluates reproducible paper scenarios and the existing signed book; training/validation/held-out windows, selected parameters, rejected candidates and all costs remain visible. No zero-loss claim is inferred from zero exposure.
5. Receipts and the public proof surface distinguish observed data, modeled results, unavailable inputs and deployment evidence. Models listed on Hugging Face are not presumed financially qualified.

Still required before any claim of useful predictive behavior: verified point-in-time datasets and rights, immutable model/prompt/config revisions, selection-bias controls, held-out and forward paper evaluation, cost sensitivity, benchmark-relative results, calibration and sufficient observations. No number of successful software tests alone closes these requirements. No transition from this research contract to unattended real-money authority is implemented.
