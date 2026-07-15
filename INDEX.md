# szl-quant receipt ledger

Append-only DSSE receipt ledger written by the `scheduled-paper` workflow.
Every file is an advisory **paper-only** decision receipt, ed25519-signed by the
engine identity pinned at `keys/engine_pubkey.json` on `main`.

Verify any entry independently:
```
node verify/verify.mjs --pubkey keys/engine_pubkey.json --dir ledger/<run-dir>/
```

Runs recorded: 1 · receipts: 5 (MEASURED from files present; cron is best-effort, gaps are honest)

| run (UTC) | receipts |
|---|---|
| 20260715T090057Z_run1 | 5 |

_Advisory research output. NOT financial advice. No execution, no custody._
