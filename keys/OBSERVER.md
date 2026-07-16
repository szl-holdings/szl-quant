# Second-observer key pin

`observer_pubkey.json` pins the ed25519 signing identity of
[szl-quant-witness](https://github.com/szl-holdings/szl-quant-witness),
the second scheduled observer (generation 5 cross-witness gossip). Its
private key lives ONLY in that repository's Actions secret
(`OBSERVER_KEY_PEM`) — never committed anywhere, never in this repo.

Provenance: generated 2026-07-16 alongside the observer repo bootstrap;
keyId `712046f22b6c6292` (sha256 of the SPKI DER, first 16 hex).

Trust note, stated plainly: the observer shares this org and maintainer.
Pinning its key here means a *forged* observation cannot enter
`witness/gossip/`; it does not make the observer a second operator.
Rotation: land a PR updating this pin + the observer repo secret together;
observations signed by a retired key stay verifiable against ledger
history only if the old pin is kept alongside (append, don't replace).
