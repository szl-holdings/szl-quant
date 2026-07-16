// SPDX-License-Identifier: Apache-2.0
// src/tsa.mjs — SECOND WITNESS: RFC 3161 trusted timestamps from an
// independent authority, verified OFFLINE against pinned trust anchors.
//
// The Rekor anchor (witness.mjs) proves inclusion in one transparency log —
// a single observer. This module adds a SECOND authority with a DIFFERENT
// root of trust: an RFC 3161 TSA countersigns the sha256 of a witness
// receipt's bytes, and the token is verified locally (CMS signature,
// certificate chain to a pinned anchor, imprint match, nonce echo) BEFORE
// the engine signs a receipt over it. Everything replays offline forever.
//
// Doctrine: REPORTED (external authority), replay-before-sign, fail-closed
// verification (any parse/signature/chain doubt = throw), honest gaps when
// an authority is unreachable. Trust anchors are pin-on-first-use, committed
// to keys/tsa/ and stated as such — this is not a WebPKI resolver.
// No 32-bit bitwise ops anywhere near sizes/lengths (DER lengths are small,
// but the house rule stands).

import { createHash, createPublicKey, verify as cryptoVerify, X509Certificate, constants as cconst } from 'node:crypto';

// ── DER primitives ─────────────────────────────────────────────────────────
export function derNode(buf, off) {
  if (off + 2 > buf.length) throw new Error('DER: truncated header');
  const tag = buf[off];
  let len = buf[off + 1];
  let hlen = 2;
  if (len === 0x80) throw new Error('DER: indefinite length forbidden');
  if (len > 0x80) {
    const n = len - 0x80;
    if (n > 4) throw new Error('DER: length of length > 4');
    if (off + 2 + n > buf.length) throw new Error('DER: truncated long length');
    len = 0;
    for (let i = 0; i < n; i++) len = len * 256 + buf[off + 2 + i];
    hlen = 2 + n;
  }
  const start = off + hlen, end = start + len;
  if (end > buf.length) throw new Error('DER: value overruns buffer');
  return { tag, start, end, header: off, constructed: (tag & 0x20) !== 0 };
}
export function derChildren(buf, node) {
  const out = [];
  let off = node.start;
  while (off < node.end) { const c = derNode(buf, off); out.push(c); off = c.end; }
  return out;
}
export function derOid(buf, node) {
  if ((node.tag & 0x1f) !== 0x06) throw new Error('DER: not an OID');
  const b = buf.subarray(node.start, node.end);
  const parts = [Math.floor(b[0] / 40), b[0] % 40];
  let v = 0;
  for (let i = 1; i < b.length; i++) {
    v = v * 128 + (b[i] & 0x7f);
    if (!(b[i] & 0x80)) { parts.push(v); v = 0; }
  }
  return parts.join('.');
}
export function derSlice(buf, node) { return buf.subarray(node.header, node.end); } // full TLV
export function derValue(buf, node) { return buf.subarray(node.start, node.end); }
export function parseGeneralizedTime(s) {
  const m = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(?:\.(\d{1,3}))?Z$/.exec(s);
  if (!m) throw new Error(`TSA: unparseable GeneralizedTime "${s}"`);
  return new Date(Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +m[6], m[7] ? +m[7].padEnd(3, '0') : 0));
}

// ── request building ───────────────────────────────────────────────────────
const derEnc = {
  len(n) { if (n < 0x80) return Buffer.from([n]); const b = []; while (n) { b.unshift(n % 256); n = Math.floor(n / 256); } return Buffer.from([0x80 + b.length, ...b]); },
  tlv(tag, val) { return Buffer.concat([Buffer.from([tag]), derEnc.len(val.length), val]); },
  seq(...p) { return derEnc.tlv(0x30, Buffer.concat(p)); },
  int(buf) { if (buf[0] & 0x80) buf = Buffer.concat([Buffer.from([0]), buf]); return derEnc.tlv(0x02, buf); },
};
const OID_SHA256_DER = Buffer.from('0609608648016503040201', 'hex');
export function buildTimestampRequest(sha256hex, nonce) {
  if (!/^[0-9a-f]{64}$/.test(sha256hex)) throw new Error('TSA: imprint must be sha256 hex');
  return derEnc.seq(
    derEnc.int(Buffer.from([1])),
    derEnc.seq(derEnc.seq(OID_SHA256_DER, Buffer.from([0x05, 0x00])), derEnc.tlv(0x04, Buffer.from(sha256hex, 'hex'))),
    derEnc.int(nonce),
    Buffer.from([0x01, 0x01, 0xff]), // certReq TRUE
  );
}

// ── OIDs ───────────────────────────────────────────────────────────────────
const OID = {
  signedData: '1.2.840.113549.1.7.2',
  tstInfo: '1.2.840.113549.1.9.16.1.4',
  contentType: '1.2.840.113549.1.9.3',
  messageDigest: '1.2.840.113549.1.9.4',
  sha256: '2.16.840.1.101.3.4.2.1',
  sha384: '2.16.840.1.101.3.4.2.2',
  sha512: '2.16.840.1.101.3.4.2.3',
  sha1: '1.3.14.3.2.26',
  rsa: '1.2.840.113549.1.1.1',
  sha256rsa: '1.2.840.113549.1.1.11',
  sha384rsa: '1.2.840.113549.1.1.12',
  sha512rsa: '1.2.840.113549.1.1.13',
  rsaPss: '1.2.840.113549.1.1.10',
  ecdsaSha256: '1.2.840.10045.4.3.2',
  ecdsaSha384: '1.2.840.10045.4.3.3',
  ecdsaSha512: '1.2.840.10045.4.3.4',
  ekuTimeStamping: '1.3.6.1.5.5.7.3.8',
};
const DIGEST_BY_OID = { [OID.sha256]: 'sha256', [OID.sha384]: 'sha384', [OID.sha512]: 'sha512' };

// ── response / token parsing ───────────────────────────────────────────────
export function parseTimestampResponse(respDer) {
  const root = derNode(respDer, 0);
  const kids = derChildren(respDer, root);
  const statusKids = derChildren(respDer, kids[0]);
  const status = respDer[statusKids[0].start]; // small INTEGER
  if (status !== 0 && status !== 1) throw new Error(`TSA: status ${status} — request not granted`);
  if (kids.length < 2) throw new Error('TSA: granted but no token present');
  return { status, tokenDer: Buffer.from(derSlice(respDer, kids[1])) };
}

export function parseToken(tokenDer) {
  const ci = derNode(tokenDer, 0);
  const ciKids = derChildren(tokenDer, ci);
  if (derOid(tokenDer, ciKids[0]) !== OID.signedData) throw new Error('TSA: token is not CMS SignedData');
  const sdSeq = derNode(tokenDer, ciKids[1].start); // content of [0] EXPLICIT = SignedData SEQUENCE
  if (sdSeq.tag !== 0x30) throw new Error('TSA: SignedData is not a SEQUENCE');
  const sdKids = derChildren(tokenDer, sdSeq);
  // version, digestAlgorithms, encapContentInfo, [0]certs?, [1]crls?, signerInfos
  const encap = sdKids[2];
  const encapKids = derChildren(tokenDer, encap);
  if (derOid(tokenDer, encapKids[0]) !== OID.tstInfo) throw new Error('TSA: eContentType is not TSTInfo');
  const eContentWrap = derChildren(tokenDer, encapKids[1])[0]; // OCTET STRING
  const tstDer = Buffer.from(derValue(tokenDer, eContentWrap));
  let certsDer = [];
  let signerInfosNode = null;
  for (let i = 3; i < sdKids.length; i++) {
    const t = sdKids[i].tag;
    if (t === 0xa0) certsDer = derChildren(tokenDer, sdKids[i]).map((c) => Buffer.from(derSlice(tokenDer, c)));
    else if (t === 0x31) signerInfosNode = sdKids[i];
  }
  if (!signerInfosNode) throw new Error('TSA: no signerInfos');
  const signerInfos = derChildren(tokenDer, signerInfosNode);
  if (signerInfos.length !== 1) throw new Error(`TSA: expected exactly 1 signerInfo, got ${signerInfos.length}`);
  const si = signerInfos[0];
  const siKids = derChildren(tokenDer, si);
  // version, sid, digestAlgorithm, [0] signedAttrs, sigAlg, signature
  let idx = 0;
  const version = tokenDer[siKids[idx++].start];
  const sidNode = siKids[idx++];
  const digestAlgOid = derOid(tokenDer, derChildren(tokenDer, siKids[idx++])[0]);
  let signedAttrsNode = null;
  if (siKids[idx].tag === 0xa0) signedAttrsNode = siKids[idx++];
  const sigAlgNode = siKids[idx++];
  const sigAlgKids = derChildren(tokenDer, sigAlgNode);
  const sigAlgOid = derOid(tokenDer, sigAlgKids[0]);
  const signature = Buffer.from(derValue(tokenDer, siKids[idx++]));
  if (!signedAttrsNode) throw new Error('TSA: signedAttrs missing (required by RFC 3161)');
  // signedAttrs: content-type + message-digest
  let ctOk = false, mdHex = null;
  for (const attr of derChildren(tokenDer, signedAttrsNode)) {
    const ak = derChildren(tokenDer, attr);
    const aoid = derOid(tokenDer, ak[0]);
    const aval = derChildren(tokenDer, ak[1])[0];
    if (aoid === OID.contentType) ctOk = derOid(tokenDer, aval) === OID.tstInfo;
    if (aoid === OID.messageDigest) mdHex = Buffer.from(derValue(tokenDer, aval)).toString('hex');
  }
  if (!ctOk) throw new Error('TSA: signedAttrs content-type is not TSTInfo');
  if (!mdHex) throw new Error('TSA: signedAttrs has no message-digest');
  // re-encode signedAttrs [0] IMPLICIT → SET OF (0x31) for signature input
  const rawAttrs = Buffer.from(derSlice(tokenDer, signedAttrsNode));
  rawAttrs[0] = 0x31;
  // TSTInfo fields
  const tst = derNode(tstDer, 0);
  const tk = derChildren(tstDer, tst);
  const policyOid = derOid(tstDer, tk[1]);
  const impKids = derChildren(tstDer, tk[2]);
  const impAlgOid = derOid(tstDer, derChildren(tstDer, impKids[0])[0]);
  const imprintHex = Buffer.from(derValue(tstDer, impKids[1])).toString('hex');
  const serialHex = Buffer.from(derValue(tstDer, tk[3])).toString('hex');
  const genTimeStr = Buffer.from(derValue(tstDer, tk[4])).toString('latin1');
  let nonceHex = null;
  for (let i = 5; i < tk.length; i++) {
    if ((tk[i].tag & 0x1f) === 0x02 && tk[i].tag === 0x02) { nonceHex = Buffer.from(derValue(tstDer, tk[i])).toString('hex').replace(/^00/, ''); break; }
  }
  return {
    tstDer, certsDer, sidNode: { sid: Buffer.from(derSlice(tokenDer, sidNode)) },
    digestAlgOid, sigAlgOid, sigAlgNode: Buffer.from(derSlice(tokenDer, sigAlgNode)), signature, rawAttrs, mdHex,
    tstInfo: { policyOid, impAlgOid, imprintHex, serialHex, genTime: parseGeneralizedTime(genTimeStr), genTimeStr, nonceHex },
  };
}

// ── offline verification ───────────────────────────────────────────────────
function findSignerCert(parsed) {
  const sidDer = parsed.sidNode.sid;
  const sidRoot = derNode(sidDer, 0);
  if (sidRoot.tag !== 0x30) throw new Error('TSA: subjectKeyIdentifier SID unsupported (expected issuerAndSerial)');
  const sidKids = derChildren(sidDer, sidRoot);
  const serialHex = Buffer.from(derValue(sidDer, sidKids[1])).toString('hex');
  for (const der of parsed.certsDer) {
    const x = new X509Certificate(der);
    const certSerial = x.serialNumber.toLowerCase().replace(/^0+/, '');
    if (certSerial === serialHex.replace(/^0+/, '').toLowerCase()) return { x, der };
  }
  throw new Error('TSA: signer certificate not present in token');
}
function verifySig(parsed, pubKey) {
  const data = parsed.rawAttrs;
  const digest = DIGEST_BY_OID[parsed.digestAlgOid];
  if (!digest) throw new Error(`TSA: unsupported digest ${parsed.digestAlgOid}`);
  const sig = parsed.signature;
  const alg = parsed.sigAlgOid;
  if (alg === OID.rsa || alg === OID.sha256rsa || alg === OID.sha384rsa || alg === OID.sha512rsa) {
    if (!cryptoVerify(digest, data, pubKey, sig)) throw new Error('TSA: CMS signature INVALID (RSA)');
  } else if (alg === OID.rsaPss) {
    if (!cryptoVerify(digest, data, { key: pubKey, padding: cconst.RSA_PKCS1_PSS_PADDING, saltLength: cconst.RSA_PSS_SALTLEN_AUTO }, sig)) throw new Error('TSA: CMS signature INVALID (RSA-PSS)');
  } else if (alg === OID.ecdsaSha256 || alg === OID.ecdsaSha384 || alg === OID.ecdsaSha512) {
    if (!cryptoVerify(digest, data, { key: pubKey, dsaEncoding: 'der' }, sig)) throw new Error('TSA: CMS signature INVALID (ECDSA)');
  } else throw new Error(`TSA: unsupported signature algorithm ${alg}`);
}
export function assertNonceEcho(expectedNonceHex, actualNonceHex) {
  if (expectedNonceHex === null) return;
  if (actualNonceHex === null) throw new Error('TSA: requested nonce echo is missing');
  let expected;
  let actual;
  try {
    expected = BigInt('0x' + expectedNonceHex);
    actual = BigInt('0x' + actualNonceHex);
  } catch {
    throw new Error('TSA: nonce echo is not a valid hexadecimal INTEGER');
  }
  if (actual !== expected) throw new Error('TSA: nonce echo mismatch');
}
export function verifyTimestampToken({ tokenDer, expectedImprintHex, anchors, expectedNonceHex = null, now = null }) {
  if (!anchors?.length) throw new Error('TSA: no pinned trust anchors provided — refusing to verify against nothing');
  const parsed = parseToken(tokenDer);
  const t = parsed.tstInfo;
  if (t.impAlgOid !== OID.sha256) throw new Error(`TSA: imprint algorithm is not sha256 (${t.impAlgOid})`);
  if (t.imprintHex !== expectedImprintHex) throw new Error('TSA: messageImprint does NOT match the witnessed bytes');
  assertNonceEcho(expectedNonceHex, t.nonceHex); // value compare: DER echoes are minimal integers
  const md = createHash(DIGEST_BY_OID[parsed.digestAlgOid]).update(parsed.tstDer).digest('hex');
  if (md !== parsed.mdHex) throw new Error('TSA: signedAttrs message-digest does not match TSTInfo content');
  const { x: signer, der: signerDer } = findSignerCert(parsed);
  verifySig(parsed, signer.publicKey);
  const eku = (signer.keyUsage || []);
  if (!eku.includes(OID.ekuTimeStamping)) throw new Error(`TSA: signer certificate lacks the timeStamping EKU (${JSON.stringify(eku)})`);
  // chain walk: signer → … → a cert byte-equal to a pinned anchor
  const anchorRaw = anchors.map((pem) => new X509Certificate(pem).raw);
  const pool = parsed.certsDer.map((d) => new X509Certificate(d));
  const chain = [signer];
  let cur = signer, curDer = signerDer, hops = 0;
  const atTime = t.genTime;
  while (true) {
    if (anchorRaw.some((a) => a.equals(cur.raw))) break; // reached a pin
    if (++hops > 6) throw new Error('TSA: chain too long / does not reach a pinned anchor');
    const issuer = pool.find((c) => cur.checkIssued(c)) || anchors.map((pem) => new X509Certificate(pem)).find((c) => cur.checkIssued(c));
    if (!issuer) throw new Error(`TSA: no issuer found for "${cur.subject.split('\n').pop()}" — chain does not reach a pinned anchor`);
    if (!cur.verify(issuer.publicKey)) throw new Error('TSA: certificate signature INVALID in chain');
    cur = issuer; chain.push(issuer);
  }
  for (const c of chain) {
    if (atTime < new Date(c.validFrom) || atTime > new Date(c.validTo)) {
      throw new Error(`TSA: certificate "${c.subject.split('\n').pop()}" not valid at genTime ${t.genTimeStr}`);
    }
  }
  if (now && t.genTime > new Date(now.getTime() + 24 * 3600 * 1000)) throw new Error('TSA: genTime is in the future');
  return {
    genTime: t.genTime.toISOString(), genTimeRaw: t.genTimeStr, policyOid: t.policyOid,
    serialHex: t.serialHex, signerSubject: signer.subject.replace(/\n/g, ', '),
    anchorSubject: chain[chain.length - 1].subject.replace(/\n/g, ', '), chainLength: chain.length,
  };
}

// ── receipt naming/body ────────────────────────────────────────────────────
export const TSA_FILE_RE = /^tsa_(\d{4})_(\d+)\.receipt\.json$/;
export const tsaFileName = (seq, ts) => `tsa_${String(seq).padStart(4, '0')}_${ts}.receipt.json`;
export function buildTsaBody({ seq, witnessFile, witnessSha256, authority, verified, tokenDerBase64, nonceHex, backfilled, capturedAt }) {
  return {
    kind: 'szl-quant-witness-tsa',
    label: 'REPORTED',
    statement: `RFC 3161 timestamp from an INDEPENDENT authority over witness receipt bytes for chain link seq ${seq} — a second witness with a different root of trust than the transparency log, verified offline before signing.`,
    seq, witness: { receiptFile: witnessFile, receiptSha256: witnessSha256 },
    authority, // { name, url }
    token: { derBase64: tokenDerBase64, nonceHex },
    verifiedBeforeSigning: {
      genTime: verified.genTime, policyOid: verified.policyOid, serialHex: verified.serialHex,
      signerSubject: verified.signerSubject, anchorSubject: verified.anchorSubject, chainLength: verified.chainLength,
    },
    backfilled, capturedAt,
    limits: backfilled
      ? 'Backfilled: genTime proves the bytes existed no later than the timestamp instant, which is later than sealing. Trust anchor is pin-on-first-use, committed in keys/tsa/ — not a WebPKI resolution.'
      : 'genTime proves the bytes existed no later than the timestamp instant. Trust anchor is pin-on-first-use, committed in keys/tsa/ — not a WebPKI resolution.',
  };
}
