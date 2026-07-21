# szl-quant receipt ledger

Append-only DSSE receipt ledger written by the `scheduled-paper` workflow.
Every file is an advisory **paper-only** decision receipt, ed25519-signed by the
engine identity pinned at `keys/engine_pubkey.json` on `main`.

Verify any entry independently:
```
node verify/verify.mjs --pubkey keys/engine_pubkey.json --dir ledger/<run-dir>/
```

Runs recorded: 34 · receipts: 350 (MEASURED from files present; cron is best-effort, gaps are honest)

Track record (latest, MEASURED from verified receipts only): +1d n=0 hit=— pending=0 · +7d n=0 hit=— pending=0 · no-calls(BLOCKED)=132 — a past frequency, NOT a prediction

Hash chain: 32 link(s), head seq 32 sha256 73aa35e53993… — every sealed run tamper-evident; walk it: `node verify/verify.mjs --pubkey keys/engine_pubkey.json --chain ledger/`

Paper book (MODELED, paper-only — NOT real funds): seq 26 · equity $10000.000000 · open positions 0 · fills this run 0 · replay it: `node verify/verify.mjs --pubkey keys/engine_pubkey.json --book ledger/`

Refusal record (MEASURED): latest run BLOCKED 3/6 — conviction×2 liquidity×1 · lifetime (recorded runs) 97/150 — liquidity×53 conviction×44 · a refusal is a decision, not an absence · replay: `node verify/verify.mjs --pubkey keys/engine_pubkey.json --refusals ledger/`

External witness (REPORTED, SET + Merkle inclusion + log consistency offline-verifiable): chain head seq 32 anchored in Rekor — logIndex 2211405344, uuid 108e9186e8c5677a… · heads anchored 32/32 · inclusion proven offline 32/32 · log consistency 31/31 adjacent checkpoint pair(s) receipted · second witness (RFC 3161) 32/32 head(s) countersigned · cross-witness gossip 19 observation(s) from a second scheduled observer · an anchored head cannot be silently truncated · check: `node verify/verify.mjs --pubkey keys/engine_pubkey.json --witness .`

| run (UTC) | receipts |
|---|---|
| 20260715T090057Z_run1 | 5 |
| 20260715T092114Z_run2 | 6 |
| 20260715T094346Z_run3 | 9 |
| 20260715T141549Z_run4 | 9 |
| 20260715T194057Z_run5 | 9 |
| 20260716T034408Z_run6 | 9 |
| 20260716T083822Z_run7 | 9 |
| 20260716T142836Z_run8 | 9 |
| 20260716T173736Z_run9 | 10 |
| 20260716T175421Z_run10 | 11 |
| 20260716T183506Z_run12 | 11 |
| 20260716T185648Z_run13 | 11 |
| 20260716T193525Z_run14 | 11 |
| 20260716T193839Z_run15 | 11 |
| 20260716T202015Z_run16 | 11 |
| 20260716T205840Z_run17 | 11 |
| 20260717T034344Z_run18 | 11 |
| 20260717T083225Z_run19 | 11 |
| 20260717T140759Z_run20 | 11 |
| 20260717T193725Z_run21 | 11 |
| 20260718T033902Z_run22 | 11 |
| 20260718T081319Z_run23 | 11 |
| 20260718T135458Z_run24 | 11 |
| 20260718T193657Z_run25 | 11 |
| 20260719T040053Z_run26 | 11 |
| 20260719T083827Z_run27 | 11 |
| 20260719T135816Z_run28 | 11 |
| 20260719T193725Z_run29 | 11 |
| 20260720T041006Z_run30 | 11 |
| 20260720T093941Z_run31 | 11 |
| 20260720T143704Z_run32 | 11 |
| 20260720T200051Z_run33 | 11 |
| 20260721T035212Z_run34 | 11 |
| 20260721T090551Z_run35 | 11 |

_Advisory research output. NOT financial advice. No execution, no custody._
