# Methodology — and its honest limits

Every number this engine emits carries a canon label. This file states what
the labels mean HERE, and exactly what the backtests do and do not show.

## Data

| Source | What | Label | Why |
|---|---|---|---|
| CoinGecko public API | daily close history | **REPORTED** | external feed; we did not verify venue prints |
| Dexscreener public API | live pair snapshots (price, liquidity, 24h volume) | **REPORTED** | external feed; unverified |
| Backtest replay of pinned history | return, drawdown, trade counts | **MEASURED** | deterministic replay of real observed history; dataset sha256 pinned in the receipt |
| Fee + slippage model (30 bps + 20 bps) | simulated fill costs | **MODELED** | assumption, not observation — stated in every fill |
| Strategy transforms (momentum squash, z-score, Hoeffding-shape confidence) | component scores | **HEURISTIC** | rule-based; market iid/boundedness assumptions do not hold |
| Feed failure / missing price | — | **UNAVAILABLE** | carries NO value; the engine abstains or BLOCKS, it never fills gaps |

## Backtest protocol (MEASURED)

- Daily bars; decisions at close *t* are filled at close *t+1* — no lookahead.
- Long-only, no leverage, no shorting (v1 paper book enforces this in code).
- Costs applied to every simulated fill, embedded in the effective price
  (charged exactly once).
- Walk-forward split: first 70% in-sample, remainder out-of-sample.
- The **full parameter population is reported** — every config in the declared
  grid, both windows. Picking the best cell after the fact is multiple
  testing (Bailey & López de Prado); the receipt keeps the whole population
  visible so nobody (including us) can quietly cherry-pick.

## What the backtests do NOT show

- **No predictive claim.** MEASURED means "this replay of that history
  produced these numbers" — nothing more. Past performance does not predict
  future results.
- **Small-n warnings are in-band:** win rates on fewer than 10 round trips
  are flagged as statistically weak evidence inside the result itself.
- **Deflated expectations:** with a 5-config grid there is nonzero
  probability the best cell is luck. We report the population instead of a
  "deflated Sharpe" figure because our n (daily bars, one asset per replay)
  is too small for that statistic to be honest.
- **Costs are MODELED.** Real Solana memecoin slippage is regime-dependent
  and can exceed 20 bps badly in thin books; the liquidity gate exists
  precisely because the cost model goes wrong in thin pools.
- Λ conviction roll-ups are **ADVISORY** (Λ uniqueness = Conjecture 1, open).
  Conviction is capped at the 0.97 trust ceiling; nothing here reaches
  certainty, by law.

## Risk gates (fail closed)

posture (paper-only, structural) · loop-tax budget (ouroboros ledger) ·
data freshness · sample size · liquidity floors · volatility ceiling ·
conviction floor + trust-ceiling law. ANY blocked gate ⇒ the decision
verdict is **BLOCKED**, signed as BLOCKED, with the blocking gates and
their reasons in the receipt. There is no code path that flips a verdict.

## Receipts

Every signal decision, backtest run, and paper session is wrapped in a
DSSE envelope (spec-exact PAE, ed25519, keyid = sha256(SPKI)[:16]) over an
in-toto v1 Statement. `verify/verify.mjs` is an independent verifier that
imports nothing from `src/` — it re-implements canonicalization, PAE and
the doctrine checks, so a third party can audit receipts without trusting
engine code. Verify with:

```bash
node verify/verify.mjs --pubkey keys/engine_pubkey.json --dir receipts/
```

## Data sources & fallback honesty

Daily history: **CoinGecko public** (USD) is primary; on failure the engine
falls back to **Coinbase Exchange public candles** (genuine USD quotes,
≤300 daily buckets per windowed request — a 365d fetch pages twice). Both
feeds are external ⇒ **REPORTED**. Every receipt's dataset block pins the
serving source, its URL, the exact series bytes (sha256) and a
`sourceChain` listing every attempt and outcome. One series always comes
from ONE source — mixed-source stitching is forbidden. Both sources down ⇒
**UNAVAILABLE**, fail closed: nothing cached, nothing synthesized. Live
pair snapshots come from Dexscreener public (REPORTED).

Source selection was itself measured, not assumed: Binance public klines
were evaluated first and **rejected** — api.binance.com answers HTTP 451
(geo-restricted) from US egress, and both the dev environment and
GitHub-hosted CI runners are US-based, so that "fallback" could never
fire where this engine actually runs (observed 2026-07-15). The
autonomous ledger (see README) adds no new claims: it only accumulates
the same signed receipts on a schedule.

## Track-record protocol

The track record (`bin/quant.mjs track`) is computed ONLY from
DSSE-verified signal receipts checked against the pinned engine pubkey —
unverifiable files are excluded and listed by name in the report (nothing
silently dropped). Population is the FULL emission history: ALLOWED
`ENTER_LONG` signals are scored; BLOCKED no-calls are tallied (refusing
bad conditions is part of the record). For each scored signal,
baseline = first daily close at/after the decision time and outcome =
first daily close at/after decision time + horizon, BOTH from one source
series (sha256-pinned per row); the DEX snapshot price is REPORTED
context only and never enters the return math. Horizons not yet elapsed
are UNAVAILABLE ("pending", with the date they become measurable);
elapsed horizons with missing history are honest gaps. Hit-rate is a
measured frequency of realized past outcomes — never a probability
claim — and carries an in-band weak-evidence note below n=10. The report
itself is DSSE-signed (predicate
`https://szl.holdings/quant/track-record/v1`) and regenerated on every
scheduled ledger run, so the scoreboard can be independently verified
with the same `verify/verify.mjs` as any other receipt.

## Ledger hash chain

The ledger branch is append-only by convention; chain receipts (predicate
`https://szl.holdings/quant/chain/v1`) make that convention checkable.
Each scheduled run seals its run dir — sha256 of every non-chain receipt
file — into a signed chain receipt that also pins the sha256 of the
previous chain receipt's bytes. Genesis (seq 1) backfilled every
pre-chain run dir. `verify/verify.mjs --chain ledger/` independently
walks the chain: DSSE signature per link against the pinned key, seq
contiguity from 1, prev-pointer byte-hash linkage, exactly-once dir
coverage, and per-file sha256 equality against disk — so rewriting or
deleting any sealed run breaks the walk loudly. Honest limit, stated
in every link: wholesale deletion of the newest link(s) (head
truncation) is not detectable by the chain alone; GitHub Actions run
logs and the git history of INDEX.md act as external witnesses.

## Stateful paper book (MODELED)

From book seq 1 onward, every scheduled run advances a cross-run paper
book: a signed `book_*.receipt.json` whose state transition is exactly
replayable from the DSSE-verified signal receipts in the same run dir.
`verify --book ledger/` reimplements the frozen v1 rules independently
and recomputes every fill, state and mark; byte-exact agreement is
required, so a book that cannot be replayed fails loudly.

Frozen v1 rules:
- Only decisions from receipts that verify against the pinned engine key
  move the book; unverifiable files are excluded and listed in-band.
- `ALLOWED ENTER_LONG` buys `entryFractionBps` (10%) of current equity at
  the decision-time REPORTED price with MODELED fee+slippage bps; no
  leverage, no pyramiding, no shorting. `ALLOWED EXIT_LONG` sells the
  full position. Anything BLOCKED leaves the book untouched — the gates
  hold the book (fail closed).
- Missing price ⇒ no fill; if an open position is unpriced, equity is
  `null` with a note — an honest empty, never an invented mark.
- Config (starting cash, sizing, cost model) is pinned at genesis and
  inherited unchanged; the verifier fails any mid-stream drift.
- Each receipt pins its predecessor by sha256 of the exact bytes; gaps
  (pre-book history, skipped runs) are declared in-band and checked
  against the ledger's actual directory list.

What the book does NOT claim: no depth/latency/partial-fill realism, no
real funds, no performance promise. Equity is MODELED over REPORTED
marks. Starting capital (10,000 paper USD) is a declared simulation
constant, not money.

## Refusal record (MEASURED)

Each scheduled run also emits a signed `refusals_*.receipt.json`: a
census of that run's decisions — verdict, proposed action, echoed
conviction (HEURISTIC, ceiling-capped upstream), and the exact gates in
`blockedBy`. Counts are MEASURED over the DSSE-verified decision
receipts in the run dir alone; unverifiable files are excluded and
confessed in-band. `verify --refusals ledger/` recomputes every count
from the signed receipts — the census must replay byte-exact.

Why this exists: the record is refusal-dominated (conviction floor 0.55
vs low Hoeffding-shaped sample confidence at ~120 daily observations),
and doctrine requires the reasons to be countable on the ledger rather
than explained away in prose. Limits, stated plainly: the census says
WHY entries were refused, not whether refusing was right; per-run scope
only; no performance claim of any kind.

## External witness (REPORTED, offline-verifiable)

The hash chain confesses one limit: deleting the newest link(s) leaves
no local trace. After each run seals its chain link, the engine anchors
the head in the Sigstore Rekor public transparency log: the head's exact
bytes, ed25519-signed, submitted as a full-content `rekord` entry (the
chain receipt is already public data). Rekor's acceptance — logIndex,
integratedTime and its own ECDSA signature (the SET) — is stored in a
signed `witness/witness_*.receipt.json`.

Labels, honestly: the Rekor response is REPORTED (an external service's
statement). What earns it a place in the verify gate is that the SET
replays OFFLINE against the Rekor public key pinned in this repo:
`verify --witness .` recomputes the head's sha256 from disk, checks the
entry anchors exactly those bytes under exactly the pinned engine key,
and verifies the SET — zero network. Limits, stated plainly: only
witnessed heads are protected and outage gaps are counted in the open;
the SET proves acceptance at integratedTime, not Merkle inclusion (an
online check against the signed tree head can do that independently).

### Merkle inclusion, replayed offline (external witness, generation 2)

The SET proves Rekor *accepted* an entry. Generation-2 witness receipts
go further and capture the **RFC 6962 inclusion proof** returned at
anchor time: the audit path (sibling hashes), the shard-tree leaf index
and size, and the **checkpoint** — Rekor's signed note over the tree
root. The verifier replays all of it with zero network and zero trust
in the engine's own code (self-contained mirrors): recompute the leaf
hash from the entry bytes (`sha256(0x00 || body)`), walk the path with
domain-separated node hashing (`sha256(0x01 || l || r)`) enforcing
exact path consumption, require the computed root to equal the
checkpoint's root, and verify the checkpoint's ECDSA signed note
against the pinned `keys/rekor_pubkey.pem` (4-byte key hint must match
`sha256(SPKI)[0..4]`). Backfilled links (`witness --all`) are labeled
what they are: the anchor proves existence **no later than**
integratedTime, which for backfill is later than sealing. Stated
limit: inclusion is proven against the checkpoint captured at anchor
time; checkpoint-to-checkpoint consistency (gossip/witness cosigning)
is not verified offline here.
