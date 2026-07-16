# Pinned TSA anchors — pin-on-first-use

Captured 2026-07-16 from live RFC 3161 responses (`certReq=TRUE`); the
anchor is the final certificate of the chain each authority returned.
These pins — not WebPKI resolution — are the trust roots the engine and
verifier accept. Rotating an anchor requires a PR that states why.

## digicert_anchor.pem
- subject: `C = US, O = DigiCert Inc, OU = www.digicert.com, CN = DigiCert Trusted Root G4`
- notAfter: `Nov  9 23:59:59 2031 GMT`
- sha256(PEM): `3aebcbe5144487ac3dbdac02369da773968addcae886d7449fbbf31bf496824d`

## freetsa_anchor.pem
- subject: `O = Free TSA, OU = Root CA, CN = www.freetsa.org, emailAddress = busilezas@gmail.com, L = Wuerzburg, ST = Bayern, C = DE`
- notAfter: `Mar  7 01:52:13 2041 GMT`
- sha256(PEM): `2151b61137ffa86bf664691ba67e7da0b19f98c758e3d228d5d8ebf27e044438`

A token must satisfy, offline: CMS signature by the signing cert, EKU
id-kp-timeStamping, chain walking byte-equal onto one of these pins,
validity at genTime, imprint match, and nonce echo (integer compare).
