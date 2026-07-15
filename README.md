<div align="center">

# szl-quant

### Doctrine-governed quant research engine — every advisory signal ships with a DSSE-signed receipt a third party can verify offline.

[![License](https://img.shields.io/badge/License-Apache_2.0-5b8dee.svg?style=flat-square)](LICENSE)
[![Receipts](https://img.shields.io/badge/signals-DSSE_receipted-3af4c8?style=flat-square)](verify/verify.mjs)
[![Posture](https://img.shields.io/badge/posture-ADVISORY_·_PAPER_ONLY-d7b96b?style=flat-square)](docs/METHODOLOGY.md)
[![Doctrine v11](https://img.shields.io/badge/Doctrine-v11-5b8dee?style=flat-square)](https://github.com/szl-holdings/.github/tree/main/doctrine)
[![SLSA](https://img.shields.io/badge/SLSA-L1_honest-3af4c8?style=flat-square)](https://slsa.dev/spec/v1.0/levels)

[SZL Holdings](https://a-11-oy.com) · [Hugging Face](https://huggingface.co/SZLHOLDINGS) · [GitHub Org](https://github.com/szl-holdings)

</div>

> ## Honest scope box — read this first
> **Advisory research system. PAPER ONLY. NOT financial advice.**
> This engine emits *signed research signals* and keeps a *simulated* paper
> book. There is **no order execution, no exchange/wallet integration, no
> custody** — those code paths do not exist. Backtest results are
> **MEASURED replays of real history** and predict nothing. Λ conviction
> roll-ups are **ADVISORY** (Λ uniqueness = Conjecture 1, open). Confidence
> is capped at the **0.97 trust ceiling** — nothing here reaches certainty,
> by law.

## Why this exists

Solana "calls" accounts post unverifiable, hindsight-editable wins.
Serious systematic shops publish methodology and warn about backtest
overfitting. `szl-quant` takes the leaders' lessons and rebuilds them in
SZL's shape (see [docs/RESEARCH_MEMO.md](docs/RESEARCH_MEMO.md)): **the
differentiator is verifiable trading provenance** — every signal, backtest
and paper session is wrapped in a DSSE envelope (spec-exact PAE, ed25519,
in-toto v1 Statement) at emission time, so cherry-picking and post-hoc
editing are cryptographically impossible, and every risk-gate rejection is
an honest **BLOCKED** verdict inside the signed record.

## Pipeline

```
ingest (REPORTED feeds)            doctrine layer
  coingecko daily history   ┐        · honesty labels on every value
  dexscreener live pairs    ├──►  strategy (HEURISTIC, formula-canon Λ roll-up)
                            │        · tsmom + meanrev → Λ conviction ≤ 0.97
                            │      risk gates (FAIL CLOSED → BLOCKED verdicts)
                            │        · posture · loop-tax · freshness · sample
                            │        · liquidity · volatility · conviction
                            └──►  paper book (deterministic, MODELED costs)
                                       │
                              DSSE-signed receipt per decision
                                       │
                            verify/verify.mjs (independent, offline)
```

The engine's feedback loop runs inside an **ouroboros bounded loop**: each
observe→signal→gate→account cycle charges **loop tax** against a governance
budget; an exhausted ledger BLOCKS further emission (`budgetExhausted` is an
honest exit, not a failure to hide).

## Quickstart

```bash
# no dependencies — Node ≥ 20, stdlib only (everything vendored, no runtime CDNs)
npm test                      # 14 unit tests: doctrine invariants, DSSE, gates, determinism

node bin/quant.mjs backtest   # MEASURED walk-forward backtests on real public history
node bin/quant.mjs paper      # one live paper session (REPORTED feeds) → signed signals

# independent verification (imports nothing from src/):
node verify/verify.mjs --pubkey keys/engine_pubkey.json --dir receipts/
```

Feeds down? The engine emits an **honest empty** (`UNAVAILABLE`, zero
signals, still signed) — it never synthesizes a number.

## What a receipt proves — and what it does NOT

- ✅ **Authorship + integrity + time-of-emission binding**: ed25519 over
  spec-exact PAE; subject digest pins the exact canonical decision bytes;
  keyid = sha256(SPKI)[:16] (house convention; pin `keys/engine_pubkey.json`).
- ✅ **Honest verdicts**: a BLOCKED decision is signed as BLOCKED — there is
  no code path that flips it.
- ❌ It does **NOT** prove the signal is *good*. MEASURED backtests describe
  the past; nothing here claims predictive performance.
- ❌ It does **NOT** upgrade advisory Λ to proven trust — `provenTrust` is
  structurally locked `false` (govsign pattern).

## Repo map

| Path | What |
|---|---|
| `src/canon.mjs` | doctrine constants: labels, 0.97 ceiling, locked-proven set, posture |
| `src/formulas.mjs` | Λ aggregate (D2 shape) + bounds, Hoeffding shape, returns/z-score/vol |
| `src/strategy.mjs` | tsmom + meanrev → Λ conviction (ADVISORY, capped) |
| `src/gates.mjs` | fail-closed gates → ALLOWED / BLOCKED with reasons |
| `src/ouroboros.mjs` | bounded loop + loop-tax ledger (adapted from szl-holdings/ouroboros) |
| `src/portfolio.mjs` | deterministic paper book, integer micro-USD, MODELED costs |
| `src/backtest.mjs` | walk-forward MEASURED replays, full-population reporting |
| `src/receipts.mjs` + `src/dsse.mjs` | in-toto Statement + DSSE envelope (ed25519) |
| `verify/verify.mjs` | independent verifier (no `src/` imports) |
| `docs/RESEARCH_MEMO.md` | leaders studied → lessons → what SZL does differently |
| `docs/METHODOLOGY.md` | backtest protocol + honest limits |
| `.github/workflows/ci.yml` | CI: unit tests + receipt verification on every push/PR (SHA-pinned actions) |

## Formula-canon honesty

The locked-proven canonical set is **EXACTLY 8**: `{F1, F4, F7, F11, F12,
F18, F19, F22}` (machine-enforced upstream in
[lutar-lean](https://github.com/szl-holdings/lutar-lean)). The mapping of
this engine's local implementations onto those F-ids is **NOT asserted**
(UNKNOWN — never fabricated), and the engine never claims its signals are
"proven". Λ = Conjecture 1, never "theorem".

---

<sub>SZL Holdings · [a-11-oy.com](https://a-11-oy.com) · Doctrine v11 · SLSA L1 honest · L2 attested · L3 roadmap (this repo: L1) · trust ceiling 0.97 · Λ = Conjecture 1 · Apache-2.0 · **not financial advice, paper-only, receipts-verifiable**</sub>
