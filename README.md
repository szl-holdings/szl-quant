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
  daily history cg→coinbase ┐        · honesty labels on every value
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
npm test                      # 81 unit tests: doctrine invariants, DSSE, gates, determinism, ingest fallback, track record, hash chain, paper book, refusal record, external witness, Merkle inclusion, log consistency, RFC 3161 second witness, cross-witness gossip

node bin/quant.mjs backtest   # MEASURED walk-forward backtests on real public history
node bin/quant.mjs paper      # one live paper session (REPORTED feeds) → signed signals

# independent verification (imports nothing from src/):
node verify/verify.mjs --pubkey keys/engine_pubkey.json --dir receipts/
node verify/verify.mjs --pubkey keys/engine_pubkey.json --chain ledger/  # walk the tamper-evident hash chain
node verify/verify.mjs --pubkey keys/engine_pubkey.json --book  ledger/  # REPLAY the stateful paper book
node verify/verify.mjs --pubkey keys/engine_pubkey.json --refusals ledger/  # REPLAY the refusal census
node verify/verify.mjs --pubkey keys/engine_pubkey.json --witness .         # check Rekor anchors + TSA countersignatures OFFLINE (from the ledger-branch root)
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

## Autonomous receipt ledger

The [`scheduled-paper` workflow](.github/workflows/scheduled-paper.yml) runs
a paper session roughly every 6 hours, independently re-verifies the fresh
receipts against the pinned pubkey, and appends them to the
[`ledger` branch](https://github.com/szl-holdings/szl-quant/tree/ledger) —
an append-only public record that grows without anyone touching it.

- Verify any entry offline:
  `node verify/verify.mjs --pubkey keys/engine_pubkey.json --dir ledger/<run-dir>/`
- GitHub cron is best-effort: **gaps are honest** — the ledger MEASURES what
  actually ran; it promises nothing.
- Feeds down ⇒ the run still lands an honest-empty session receipt
  (UNAVAILABLE, zero signals) — silence is never dressed up as activity.
- The CI signing key is a repo Actions secret; if it is absent the job
  **fails closed** rather than emit a single unsigned entry.

## Hash-chained ledger — deletion becomes visible

Every scheduled run seals its receipts into a signed **chain receipt**:
sha256 of every file in the run dir, plus the sha256 of the previous
chain receipt's bytes. Genesis (seq 1) backfilled every pre-chain run, so
the whole history is locked from the first link. Walk it yourself:

```bash
node verify/verify.mjs --pubkey keys/engine_pubkey.json --chain ledger/
```

Rewriting or deleting ANY sealed run now breaks the chain at that link.
Honest limit, stated plainly: wholesale deletion of the newest link(s)
(head truncation) is not detectable by the chain alone — GitHub Actions
run logs (each run's summary now carries the headline facts) and the git
history of INDEX.md act as external witnesses.

## Stateful paper book — a fund you can replay

```bash
node bin/quant.mjs book --ledger ledger/    # → signed book_*.receipt.json
node verify/verify.mjs --pubkey keys/engine_pubkey.json --book ledger/
```

From genesis onward, every scheduled run advances a cross-run **paper
book**: entries at 10% of equity on `ALLOWED ENTER_LONG`, full exits on
`ALLOWED EXIT_LONG`, MODELED bps costs, no leverage / pyramiding /
shorting — and anything BLOCKED leaves the book untouched (the gates
hold the book, fail closed).

The differentiator: the verifier does not *check* the book, it
**replays** it — every fill, state and mark is recomputed from the
DSSE-verified signal receipts alone, and byte-exact agreement is
required. Each receipt pins its predecessor by sha256, config is locked
at genesis, gaps are declared in-band, unpriced positions yield an
honest `null` equity instead of an invented mark. Paper only — the
equity is MODELED over REPORTED marks, never real funds, never a
performance claim.

## Refusal record — why the engine says no

```bash
node bin/quant.mjs refusals --ledger ledger/  # → signed refusals_*.receipt.json
node verify/verify.mjs --pubkey keys/engine_pubkey.json --refusals ledger/
```

Most of this engine's record is refusals — and that is by design, so the
refusals themselves are first-class, signed data. Each run gets a census
of every decision: verdict, proposed action, echoed conviction, and the
exact gates that blocked it. The verifier replays the counts from the
DSSE-verified decision receipts alone; a census that cannot be
recomputed fails loudly.

Honest reading of the current record: at ~120 daily observations the
Hoeffding-shaped sample confidence stays low, which keeps Λ conviction
under the 0.55 floor most days — so the conviction gate refuses. That is
the doctrine working, not a defect, and it is **not** a promise that the
engine will trade more (or better) as history accumulates.

## External witness — the ledger cannot quietly lose its head

```bash
node bin/quant.mjs witness --ledger ledger/ --witness-dir witness/        # anchor the newest head + link checkpoints
node bin/quant.mjs witness --ledger ledger/ --witness-dir witness/ --all  # backfill: every link anchored, every checkpoint pair linked
node verify/verify.mjs --pubkey keys/engine_pubkey.json --witness .       # replay anchors + inclusion + consistency + second-witness timestamps offline
```

The hash chain confesses its one blind spot: deleting the newest link(s)
leaves no local trace. So after sealing, each run anchors the head's
exact bytes in the Sigstore **Rekor** public transparency log — an
append-only log this engine does not operate. Deleting the ledger does
not delete the anchor, and the entry stays discoverable by this engine's
public key.

Honesty about trust: the Rekor response is REPORTED. It earns a place in
the verify gate because everything replays **offline** against pinned
keys — the verifier recomputes the head's sha256 from disk, confirms the
entry anchors exactly those bytes under exactly the pinned engine key,
checks the SET (Rekor's signature over the integrated entry), and then
goes further: it recomputes the entry's RFC 6962 leaf hash, walks the
captured Merkle audit path onto the checkpoint's root, and verifies that
checkpoint's signed note against `keys/rekor_pubkey.pem`. Zero network.
An attacker holding the **real engine key** still cannot fake an anchor:
the audit path must land on a root Rekor actually signed.

Between checkpoints, generation-3 **consistency receipts** chain the
observations together: an RFC 6962 consistency proof shows each captured
checkpoint's tree is a strict prefix of the next — the log only appended
between this engine's observations. The proof is replayed offline before
signing and again at verify time; a forked or rewritten log cannot
produce one, and two signed checkpoints at the same tree size with
different roots would be split-view evidence, flagged as exactly that.

A **second witness** (generation 4) narrows the single-observer limit:
each head-anchor witness receipt is countersigned by an RFC 3161
timestamp authority — a trust root entirely outside Sigstore. The engine
builds the TimeStampReq itself, and verifies the returned token offline
(signature, signing-cert EKU, chain to a pinned anchor committed in
`keys/tsa/`, imprint, nonce echo) **before** signing a REPORTED receipt
that embeds the whole token; the verifier repeats every check offline.
DigiCert is tried first, FreeTSA as fallback; both unreachable is a
counted gap, backfilled on the next run.

**Generation 5 — cross-witness gossip.** A second scheduled observer, [szl-quant-witness](https://github.com/szl-holdings/szl-quant-witness), watches the same ledger from its own vantage point: own repo, own ed25519 key (pinned at `keys/observer_pubkey.json`), own cron offset from the engine's. It re-verifies the head binding itself, verifies the engine-captured and live Rekor checkpoints under its own pin, replays the consistency proof offline BEFORE signing, and publishes signed observations. The engine fully re-verifies each observation offline (including recomputing the verdict — an observer cannot editorialize), archives them under `witness/gossip/`, accounts for them in signed gossip receipts, and the verifier sweeps every checkpoint both parties hold for split views. Same org, same operator — a second vantage point, not a second operator; every receipt says so.

**Generation 6 — standalone divergence alarm.** `verify/divergence-alarm.mjs`
is a small, self-contained script (imports nothing from `src/`, same
discipline as `verify/verify.mjs`) whose only job is to answer one
question as loudly as possible: across every gossip observation and
every witnessed checkpoint currently on disk, is there ANY divergence —
a bad DSSE signature, a claimed verdict that doesn't match independent
recomputation, or two verified checkpoints at the same tree size with
different roots? It re-derives RFC 6962 checkpoint parsing and
consistency-proof replay from scratch and trusts nothing the data
claims about itself. A clean run prints `status: CLEAN` and exits 0; any
divergence prints exactly what disagreed and exits 1 (loud, red CI) —
run it with `node verify/divergence-alarm.mjs --witness <ledger-root>`.
It does not supersede `verify.mjs --witness` (which remains the full
chain/inclusion/consistency/TSA/gossip walk); it is a narrower,
independently-runnable second pass over the same gossip surface, built
for a fast yes/no in CI. Like every gossip check in this repo, a CLEAN
verdict is REPORTED corroboration for the observation window actually on
disk — not proof of correctness, and not a trading or performance claim.

Limits, plainly: only witnessed links are protected, outage gaps and
unproven consistency edges are counted in the open, and consistency is
proven between the checkpoints THIS engine captured — one observer, not
cross-witness gossip (the RFC 3161 second witness adds a disjoint trust root; the szl-quant-witness gossip observer adds a second vantage point and key — still one operator, stated plainly). An anchor proves the bytes existed no later than
integratedTime; for backfilled links that is later than sealing, and
each receipt says which it is.

## Verifiable track record — the anti-"calls account"

```bash
node bin/quant.mjs track --ledger ledger/   # → signed trackrecord_*.receipt.json
```

Scores every past signal against what the market actually did next — and
the scoreboard is itself a DSSE-signed receipt:

- inputs are **verified receipts only**, checked against the pinned
  pubkey; tampered/unsigned files are excluded **by name** in the report;
- **full population**: BLOCKED no-calls are counted, never hidden — the
  engine's refusals are part of its record;
- realized forward returns are **MEASURED**, baseline and outcome from ONE
  source series (sha256-pinned); not-yet-elapsed horizons are honest
  UNAVAILABLE "pending" entries — never guessed, never dropped;
- hit-rate is a **past frequency, not a prediction**, and carries an
  in-band weak-evidence note until n ≥ 10;
- the scheduled ledger run regenerates it every ~6h, so the `ledger`
  branch INDEX always shows the current honest scoreboard.

An X "calls account" can delete its misses. This one cryptographically
cannot: every call is signed at emission, and the scoreboard only counts
what verifies.

## Resilient history ingest

Daily history tries **CoinGecko public** (USD) first; if it fails (the
shared public tier throttles hard), the engine falls back to **Coinbase
Exchange public candles** (genuine USD quotes). Both are external feeds ⇒
**REPORTED**. The receipt's dataset block pins the serving source, URL,
sha256 of the exact series bytes, and a `sourceChain` recording every
attempt. One series, one source — stitching is forbidden. Both down ⇒
**UNAVAILABLE**, fail closed. (Binance was evaluated and rejected for
this role: HTTP 451 geo-restriction from US egress, where both dev and
CI runners live — a fallback that cannot fire is not resilience.)

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
| `src/track.mjs` | verifiable track record — scores VERIFIED signal receipts vs realized closes, full population, signed report |
| `src/chain.mjs` | tamper-evident hash chain over ledger runs — signed links, genesis backfill, honest truncation limit |
| `src/book.mjs` | stateful cross-run paper book — signed, prev-hash-linked, verifier-REPLAYABLE transitions (MODELED, paper-only) |
| `src/refusals.mjs` | refusal record — signed per-run census of verdicts and blocking gates, verifier-replayable (MEASURED counts) |
| `src/witness.mjs` | external witness — chain links anchored in the Rekor public transparency log; SET, RFC 6962 Merkle inclusion **and** checkpoint-to-checkpoint consistency replayed offline against pinned keys (REPORTED) |
| `src/tsa.mjs` + `keys/tsa/` | second witness — RFC 3161 trusted timestamps over head-anchor receipts, verified offline against pin-on-first-use anchors before signing (REPORTED) |
| `src/gossip.mjs` + `keys/observer_pubkey.json` | cross-witness gossip — observations from the second scheduled observer (szl-quant-witness) fully re-verified offline under its pinned key: verdict recomputation, checkpoint re-verification, split-view sweep (REPORTED) |
| `src/ingest/` | REPORTED feeds — coingecko (primary) · coinbase candles (fallback, USD) · dexscreener live pairs · `history.mjs` resilient chain |
| `src/receipts.mjs` + `src/dsse.mjs` | in-toto Statement + DSSE envelope (ed25519) |
| `verify/verify.mjs` | independent verifier (no `src/` imports) |
| `docs/RESEARCH_MEMO.md` | leaders studied → lessons → what SZL does differently |
| `docs/METHODOLOGY.md` | backtest protocol + honest limits |
| `.github/workflows/ci.yml` | CI: unit tests + receipt verification on every push/PR (SHA-pinned actions) |
| `.github/workflows/scheduled-paper.yml` | autonomous ledger: paper session every ~6h → verify → append to `ledger` branch |

## Formula-canon honesty

The locked-proven canonical set is **EXACTLY 8**: `{F1, F4, F7, F11, F12,
F18, F19, F22}` (machine-enforced upstream in
[lutar-lean](https://github.com/szl-holdings/lutar-lean)). The mapping of
this engine's local implementations onto those F-ids is **NOT asserted**
(UNKNOWN — never fabricated), and the engine never claims its signals are
"proven". Λ = Conjecture 1, never "theorem".

---

<sub>SZL Holdings · [a-11-oy.com](https://a-11-oy.com) · Doctrine v11 · SLSA L1 honest · L2 attested · L3 roadmap (this repo: L1) · trust ceiling 0.97 · Λ = Conjecture 1 · Apache-2.0 · **not financial advice, paper-only, receipts-verifiable**</sub>
