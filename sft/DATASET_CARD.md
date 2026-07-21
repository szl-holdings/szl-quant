---
license: apache-2.0
task_categories:
  - text-generation
language:
  - en
tags:
  - szl
  - quant
  - provenance
  - dsse
  - receipts
  - sft
pretty_name: SZL Quant SFT v1 — receipt-derived trading-reasoning rows
size_categories:
  - 1K<n<10K
---

# szl-quant-sft-v1 — training rows with signed lineage

**Every row in this dataset is derived deterministically from a DSSE-signed backtest receipt and is recomputable bit-exact from content-addressed archives.** No row was hand-written, scraped, or synthesized by a model.

## Lineage (verifiable end-to-end)

```
CoinGecko daily closes (REPORTED venue feed)
  → szl-quant MEASURED walk-forward backtests → DSSE-signed receipts
      github.com/szl-holdings/szl-quant/receipts/backtest_*.receipt.json
  → content-addressed input archives  data/datasets/<sha256>.json
  → tools/sft-export.mjs — deterministic replay of the engine's actual
    decisions (signature-verified receipts only; fail-closed on any mismatch)
  → quant_sft_v1.jsonl  (this repo)
  → quant_sft_v1.manifest.json + DSSE receipt over the manifest
```

Each row's `provenance` block cites: source receipt path, receipt file sha256, dataset archive sha256, bar index, generator. The signed manifest pins the JSONL bytes (`jsonlSha256`).

## What the rows teach

Doctrine-governed advisory reasoning, in the engine's own voice:

- honesty labels on every value (`REPORTED` feed, `HEURISTIC` components, advisory Λ);
- conviction hard-capped at **0.97** (proven trust locked false);
- genuine **ABSTAIN** examples where history is insufficient — an absent value carries no value;
- fixed caveats in every answer: paper-only, advisory, not financial advice.

Composition (2,693 rows): `ENTER_LONG` 1,267 · `EXIT_LONG` 773 · `HOLD` 637 (downsampled 1-in-7 per stream, declared rule) · `ABSTAIN` 16. Assets: BTC, ETH, SOL, JUP (365d daily, ending 2026-07-21).

## Row format

```json
{
  "messages": [
    {"role": "system", "content": "You are SZL-Quant, a doctrine-governed advisory research analyst. LAW: …"},
    {"role": "user", "content": "{\"task\":\"advisory-signal-decision\",\"asset\":\"BTC\",\"asOfIso\":…,\"params\":…,\"evidence\":{…}}"},
    {"role": "assistant", "content": "{\"action\":\"HOLD\",\"components\":[…],\"conviction\":null,…,\"caveats\":[…]}"}
  ],
  "provenance": {
    "derivation": "deterministic-replay",
    "sourceReceipt": "receipts/backtest_BTC_365d.receipt.json",
    "receiptSha256": "…64 hex…",
    "datasetSha256": "…64 hex…",
    "barIndex": 123,
    "generator": "tools/sft-export.mjs v1"
  }
}
```

## Verify before you trust

```bash
git clone https://github.com/szl-holdings/szl-quant && cd szl-quant
npm test                      # includes sft-export verification suite
sha256sum sft/quant_sft_v1.jsonl   # must equal manifest.jsonlSha256
node verify/verify.mjs --dir receipts   # source receipts, independently
```

The manifest receipt (`quant_sft_v1.manifest.receipt.json`) is an in-toto/DSSE envelope signed by the szl-quant engine key (`keyId 5c6cf59741ade920`, pubkey committed in the repo); its subject digest pins the manifest, and the manifest pins the JSONL.

## Honest limits

- The underlying feed is **REPORTED** (public venue history) — the dataset inherits that trust level; backtest context is MEASURED replay, not market truth.
- Decisions reflect one momentum/mean-reversion strategy family on 4 assets × 365 daily bars — **narrow coverage, no claim of general market skill**.
- Labels teach the *form* of honest reasoning; they do not certify profitable trading. The source engine's own receipts state limited/negative out-of-sample results plainly.
- Receipts are attestations by a keyholder, not cryptographic proof of computation.

Advisory research data. Paper-only lineage. Not financial advice.
