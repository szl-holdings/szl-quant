# SZL Quant Engine — Research Memo

**Honesty labels used:** LIVE / MEASURED / REPORTED / MODELED / HEURISTIC / DEMO / UNAVAILABLE.
This memo studies leader patterns in the "fashion thinking" sense: observe, extract the lesson, adapt into SZL's own doctrinal shape. Never copy.

---

## Strand 1 — The X post (@Degen_calls_sol / status 2077084965209030808)

**Retrieval status: REPORTED (retrieved).** X blocks direct programmatic fetch and xcancel.com returned an anti-bot challenge, but the post *was* recoverable via a Nitter mirror and a markdown-extraction fetch of the canonical URL. Content is consistent across both sources, so we treat it as REPORTED rather than UNAVAILABLE. Engagement at capture time: ~21 likes, 2 retweets (REPORTED).

**What the post actually is — and the honest surprise.** Despite the account name ("DegenCalls", a Solana-degen handle), *this specific post is not a token call at all.* It is a listicle: "Ten repos worth knowing right now" — free open-source alternatives to paid software. Named repos include TradingAgents (a multi-agent quant trading framework where AI analyst/researcher/risk-manager roles debate before a trade), LibreChat, HyperFrames, Fincept Terminal (open Bloomberg-style terminal with analyst agents), MoneyPrinterTurbo, Agentic Inbox, VoxCPM, Flowsint, agent-skills, and Nango. Thesis line: "the serious stuff ships as a repo."

**Lesson (honest, no hype):** The account's *name* primes you to expect an unverifiable moonshot call; the *artifact* is a benign content-marketing listicle. This is itself the teaching: a handle's brand ≠ the epistemic status of any given claim. We must judge each emission on receipts, not on the source's reputation or self-labeling.

**Genre characterization (still worth stating), MEASURED against public research.** The broader "Solana calls account" genre — documented by madeonsol.com, xhuntr.com, stratiumsol.com, Galaxy Research, and an arXiv rug-pull study — operates on: (a) **unverifiable claims** — screenshots of PnL that can be fabricated or hindsight-edited; (b) **cherry-picked wins** — losers silently deleted; (c) **no receipts** — no timestamped, tamper-evident record of *when* the call was made vs. when the chart moved; (d) **survivorship bias** — only surviving accounts are visible, and "100% win rate" is a red flag, not a green one; (e) structural conflicts (bundling / pre-capture of supply / insider allocation) documented in pump.fun forensics.

**→ SZL-doctrine counterpart.**
- *"Calls posts are unverifiable / hindsight-editable"* → **Every SZL signal ships a DSSE-signed receipt at emission time.** The signature binds the claim to the moment of emission, so post-hoc editing is cryptographically impossible; a deleted loser still has a signed artifact somewhere.
- *"Cherry-picked wins / survivorship bias"* → SZL reports the **full population** of emitted signals with honesty labels; suppressing losers would break the signed-ledger invariant.
- *"Brand ≠ truth status"* → SZL never elevates a claim by its source; the honesty label (LIVE/MODELED/HEURISTIC/…) is attached to the *measurement*, not the *author*.

---

## Strand 2 — Leaders in systematic crypto quant, and methodology honesty

**Time-series momentum (TSMOM), AQR-style.** The canonical reference is Moskowitz–Ooi–Pedersen, *Time Series Momentum* (AQR/NYU). Applied to crypto, peer-reviewed and SSRN work (e.g., "Time-Series and Cross-Sectional Momentum in the Cryptocurrency Market … under Realistic Assumptions," and volume-weighted TSMOM papers) shows momentum *exists* in crypto but is **fragile once realistic frictions are applied** — fees, slippage, funding, and thin-book impact. Lesson: raw backtest edges are often just unpaid transaction costs.

**Mean-reversion / cross-sectional long-short.** Recent work (e.g., the Zenodo "Direction Is a Coin Flip, Variance Is Not" study) argues intraday profit-taking on crypto long-short portfolios is largely **volatility timing, not genuine reversion capture** — a warning against attributing PnL to the wrong mechanism.

**On-chain signals.** Papers using on-chain data to predict BTC cycles and macro-fundamental strategies (Concretum "Catching Crypto Trends," Springer sentiment-aware optimization) treat on-chain as *one factor among many*, not a crystal ball, and stress out-of-sample discipline.

**The honesty core — what serious shops publish.** Bailey/López de Prado, *The Deflated Sharpe Ratio* and *Pseudo-Mathematics and Financial Charlatanism: … Backtest Overfitting on Out-of-Sample Performance*, plus AQR's *What to Look for in a Backtest*. Consensus rules: (1) if you try N strategies, the best in-sample Sharpe is inflated — **deflate it** for the number of trials; (2) **transaction-cost realism** (fees + slippage + funding + market impact) can erase a paper edge; (3) **walk-forward / out-of-sample** validation is mandatory; in-sample fit is worthless as evidence.

**→ SZL-doctrine counterparts.**
- *Deflated Sharpe / multiple-testing inflation* → SZL's **trust ceiling of 0.97**: no signal or backtest may report confidence above 0.97, structurally denying "100% win rate"-style overclaiming.
- *Backtest overfitting → charlatanism* → SZL locks proven formulas to **EXACTLY {F1, F4, F7, F11, F12, F18, F19, F22}**; anything outside that set is not "proven" and must carry HEURISTIC/MODELED labels — no silent promotion of a curve-fit rule to "proven" status.
- *Λ is a conjecture, not a law* → **Λ = Conjecture 1, never called a "theorem."** Same discipline the deflated-Sharpe literature demands: don't dress a hypothesis as a proof.
- *Transaction-cost realism* → cost/slippage/funding modeled explicitly and labeled MODELED; live fills labeled MEASURED/LIVE. Never quote a frictionless number as if it were achievable.

---

## Strand 3 — Solana memecoin tooling & free public data APIs

**Trader-facing terminals (what they surface).** GMGN.ai, Photon, and BullX are fast multi-chain meme-trading terminals: real-time new-pair/pump.fun feeds, holder distribution, dev/bundle flags, snipe/copy-trade execution, PnL leaderboards. They are **execution + discovery UIs**, generally closed and partly paid; useful as *feature references*, not as our data source of record.

**Free public data APIs (ingest layer) — MEASURED from official docs:**

| API | Key required? | Rate limit (keyless) | Notes |
|---|---|---|---|
| **CoinGecko public** | **No key** | ~10–30 calls/min, IP-shared, dynamic | Base `https://api.coingecko.com/api/v3`. Endpoints incl. `/simple/price`, `/simple/token_price/{id}`, `/coins/markets`, `/coins/{id}/ohlc`, `/coins/{id}/market_chart`, `/search/trending`. Explicitly "not for production/high-frequency"; 429 → exponential backoff. Do **not** send api-key headers. |
| **Dexscreener** | **No key** | Pairs/DEX endpoints **300 req/min**; token-profile/boost endpoints **60 req/min** | `api.dexscreener.com`. `tokenAddresses` accepts comma-separated list, **max 30**. 429 on overflow. Strong for live DEX pair data (price, liquidity, volume). |
| **GeckoTerminal** | No key | ~10 calls/min (keyless, via CoinGecko onchain pool) | Base `https://api.geckoterminal.com/api/v2`. Onchain pools/tokens/trades/OHLCV. |
| **Birdeye** | **Yes (API key)** | Tiered/credit-based | Richer Solana on-chain data but **not keyless** — excluded from the keyless ingest path. |

**Decision (per directive): use CoinGecko public + Dexscreener, both keyless.**
- **Dexscreener** = primary live DEX/pair ingest (300 rpm headroom; batch up to 30 token addresses/call).
- **CoinGecko public** = corroborating market/OHLCV context and trending — but its ~10–30 rpm keyless ceiling means it must be **cached and backoff-guarded**, never hot-polled.
- **Birdeye** stays out of the keyless path (requires a key).

**→ SZL-doctrine counterparts.**
- *Terminals sell speed and confidence* → SZL **fails closed with honest BLOCKED verdicts** when data is missing or a risk gate trips — no fabricated fill or optimistic default.
- *Keyless rate limits are real* → freshness that can't be verified LIVE is labeled **UNAVAILABLE**, not silently backfilled with stale data. A 429 produces backoff + an honest staleness label, never an invented number.
- *Never invent numbers* → any field we can't source from a live keyless call is labeled UNAVAILABLE by construction.

---

## What SZL does differently

1. **Receipts, not screenshots.** Every signal is DSSE-signed *at emission*, making hindsight editing and cherry-picking cryptographically impossible — the direct answer to the calls-account genre.
2. **Full population, no survivorship.** Losers are retained and labeled, not deleted.
3. **Bounded confidence.** Hard **trust ceiling 0.97**; the deflated-Sharpe / multiple-testing literature is baked into the number, not left to good intentions.
4. **Proven ≠ fitted.** Only the locked set **{F1, F4, F7, F11, F12, F18, F19, F22}** is "proven"; everything else carries an honest MODELED/HEURISTIC label.
5. **Λ is Conjecture 1, never a theorem.**
6. **Costs are modeled, fills are measured.** No frictionless numbers presented as achievable.
7. **Fail closed.** Missing/blocked data yields a BLOCKED or UNAVAILABLE verdict — never an invented value.
8. **Label the measurement, not the messenger.** Honesty labels attach to data provenance, independent of source reputation.

*Sources: Nitter/X capture of the cited post; madeonsol.com, xhuntr.com, stratiumsol.com, Galaxy Research, arXiv rug-pull study; AQR/NYU TSMOM, Bailey–López de Prado Deflated Sharpe & backtest-overfitting papers, AQR "What to Look for in a Backtest"; official CoinGecko keyless-API docs, Dexscreener API reference. Numbers are REPORTED/MEASURED from those sources as labeled; none invented.*
