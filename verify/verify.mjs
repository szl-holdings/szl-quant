#!/usr/bin/env node
/**
 * verify.mjs — INDEPENDENT receipt verifier. Deliberately standalone:
 * imports NOTHING from src/ — reimplements canonical JSON, PAE and the
 * doctrine checks so it can audit the engine rather than trust it.
 *
 * Usage:
 *   node verify/verify.mjs <receipt.json> [more.json ...]
 *   node verify/verify.mjs --dir receipts/
 *   node verify/verify.mjs --pubkey keys/engine_pubkey.json <receipt.json>
 *   node verify/verify.mjs --chain ledger/   — walk the hash chain: DSSE per
 *     link, seq contiguity, prev-pointer byte-hash linkage, exactly-once dir
 *     coverage, per-file sha256 equality (rewrites/deletions become loud)
 *   node verify/verify.mjs --book ledger/    — REPLAY the stateful paper book:
 *     DSSE per link, prev-pointer linkage, then recompute every fill, state
 *     and mark from the signed signal receipts alone (frozen v1 rules) and
 *     require byte-exact agreement — a book that can't be replayed FAILS
 *
 *   Generation 7 (proof-of-recomputation): --dir additionally RECOMPUTES
 *   every backtest receipt that declares a datasetArchive — it re-derives
 *   ALL walk-forward numbers from the content-addressed dataset bytes at
 *   data/datasets/<sha256>.json and requires bit-exact agreement. A valid
 *   signature is NOT enough to publish a MEASURED claim: the numbers must
 *   recompute. (--datasets-root overrides the repo root for the archive.)
 *
 * Checks per receipt (ALL must pass):
 *   1. DSSE envelope: payloadType, base64 payload, ed25519 signature over
 *      spec-exact PAE("DSSEv1", type, payload) with keyid = sha256(SPKI)[:16].
 *   2. If --pubkey given: envelope key MATCHES the pinned key (else TOFU note).
 *   3. in-toto Statement shape; subject digest = sha256(canonical(decision)).
 *   4. Doctrine: posture ADVISORY_PAPER_ONLY + provenTrust===false;
 *      trustCeiling === 0.97 and no conviction/confidence exceeds it;
 *      locked-proven set EXACTLY {F1,F4,F7,F11,F12,F18,F19,F22};
 *      Λ status mentions Conjecture ("Conjecture 1"), never claims theorem;
 *      a BLOCKED verdict must list ≥1 blocking gate with a reason;
 *      every gate verdict ∈ {ALLOWED, BLOCKED}.
 * Exit code 0 iff every file verifies. Honest per-check output.
 */
import { createPublicKey, createHash, verify as edVerify, verify as cryptoVerify, X509Certificate, constants as cconst } from 'node:crypto';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const LOCKED = ['F1', 'F11', 'F12', 'F18', 'F19', 'F22', 'F4', 'F7']; // sorted
const CEILING = 0.97;

function canonicalize(v) {
  if (v === null || typeof v === 'number' || typeof v === 'boolean') {
    if (typeof v === 'number' && !Number.isFinite(v)) throw new Error('non-finite');
    return JSON.stringify(v);
  }
  if (typeof v === 'string') return JSON.stringify(v);
  if (Array.isArray(v)) return `[${v.map(canonicalize).join(',')}]`;
  if (typeof v === 'object') {
    return `{${Object.keys(v).sort().filter((k) => v[k] !== undefined)
      .map((k) => `${JSON.stringify(k)}:${canonicalize(v[k])}`).join(',')}}`;
  }
  throw new Error(`bad type ${typeof v}`);
}
const sha256Hex = (buf) => createHash('sha256').update(buf).digest('hex');
const pae = (t, body) => Buffer.concat([Buffer.from(`DSSEv1 ${Buffer.byteLength(t)} ${t} ${body.length} `, 'utf8'), body]);

function* walkConvictions(node, path = '$') {
  if (node && typeof node === 'object') {
    for (const [k, v] of Object.entries(node)) {
      if ((k === 'conviction' || k === 'confidence' || k === 'trust') && typeof v === 'number') yield [path + '.' + k, v];
      yield* walkConvictions(v, `${path}.${k}`);
    }
  }
}

function verifyFile(file, pinnedKey) {
  const fails = [];
  const notes = [];
  let env;
  try { env = JSON.parse(readFileSync(file, 'utf8')); } catch (e) { return { file, ok: false, fails: [`unreadable JSON: ${e.message}`] }; }
  if (env.payloadType !== 'application/vnd.in-toto+json') fails.push(`payloadType ${env.payloadType}`);
  let payloadBytes;
  try { payloadBytes = Buffer.from(env.payload, 'base64'); } catch { fails.push('payload not base64'); }
  let pub = pinnedKey;
  if (!pub && env.publicKeySpkiBase64) {
    pub = createPublicKey({ key: Buffer.from(env.publicKeySpkiBase64, 'base64'), type: 'spki', format: 'der' });
    notes.push('TOFU: verified against envelope-embedded key (pin with --pubkey for stronger trust)');
  }
  if (!pub) { fails.push('no public key'); return { file, ok: false, fails, notes }; }
  const keyid = sha256Hex(pub.export({ type: 'spki', format: 'der' })).slice(0, 16);
  const sigEntry = (env.signatures ?? []).find((s) => s.keyid === keyid);
  if (!sigEntry) fails.push(`no signature for keyid ${keyid}`);
  if (sigEntry && payloadBytes) {
    const ok = edVerify(null, pae(env.payloadType, payloadBytes), pub, Buffer.from(sigEntry.sig, 'base64'));
    if (!ok) fails.push('ed25519 signature INVALID over PAE');
  }
  let st = null;
  if (payloadBytes) {
    try { st = JSON.parse(payloadBytes.toString('utf8')); } catch { fails.push('payload not JSON'); }
  }
  if (st) {
    if (st._type !== 'https://in-toto.io/Statement/v1') fails.push(`statement _type ${st._type}`);
    const d = st.predicate?._doctrine;
    if (!d) fails.push('missing _doctrine block');
    else {
      if (d.posture?.mode !== 'ADVISORY_PAPER_ONLY') fails.push('posture not ADVISORY_PAPER_ONLY');
      if (d.posture?.provenTrust !== false) fails.push('provenTrust not locked false');
      if (d.trustCeiling !== CEILING) fails.push(`trustCeiling ${d.trustCeiling} ≠ ${CEILING}`);
      const locked = [...(d.lockedProvenFormulaIds ?? [])].sort();
      if (JSON.stringify(locked) !== JSON.stringify(LOCKED)) fails.push('locked-proven set not EXACTLY the canonical 8');
      const lam = String(d.lambdaStatus ?? '');
      if (!/conjecture 1/i.test(lam)) fails.push('Λ status missing "Conjecture 1"');
      if (/theorem/i.test(lam)) fails.push('Λ status claims "theorem" — doctrine violation');
    }
    for (const [p, v] of walkConvictions(st.predicate)) {
      if (v > CEILING) fails.push(`${p} = ${v} exceeds trust ceiling ${CEILING}`);
    }
    const dec = st.predicate?.decision ?? st.predicate?.summary ?? null;
    if (dec && st.subject?.[0]?.digest?.sha256) {
      const recomputed = sha256Hex(Buffer.from(canonicalize(dec), 'utf8'));
      if (recomputed !== st.subject[0].digest.sha256) fails.push('subject digest ≠ sha256(canonical(decision))');
    } else if (!st.subject?.[0]?.digest?.sha256) fails.push('missing subject digest');
    const gates = dec?.gates ?? [];
    for (const g of gates) {
      if (g.verdict !== 'ALLOWED' && g.verdict !== 'BLOCKED') fails.push(`gate ${g.gate} has non-canon verdict ${g.verdict}`);
    }
    if (dec?.verdict === 'BLOCKED') {
      const blocking = gates.filter((g) => g.verdict === 'BLOCKED');
      if (blocking.length === 0) fails.push('verdict BLOCKED but no blocking gate listed');
      if (blocking.some((g) => !g.reason)) fails.push('blocking gate missing honest reason');
    }
  }
  return { file, ok: fails.length === 0, fails, notes, keyid };
}

// ---- chain walk (self-contained; trusts only the pinned key + disk) ----
const CHAIN_RE = /^chain_\d{4}\.receipt\.json$/;

function verifyChain(ledgerDir, pinnedKey) {
  let dirs;
  try {
    dirs = readdirSync(ledgerDir, { withFileTypes: true }).filter((e) => e.isDirectory()).map((e) => e.name).sort();
  } catch (e) { console.log(`CHAIN FAIL: cannot read ${ledgerDir}: ${e.message}`); return false; }
  const problems = [];
  const links = [];
  const dirFiles = {};
  for (const d of dirs) {
    const names = readdirSync(join(ledgerDir, d), { withFileTypes: true }).filter((e) => e.isFile()).map((e) => e.name).sort();
    dirFiles[d] = names.filter((n) => n.endsWith('.json') && !CHAIN_RE.test(n));
    const chainFiles = names.filter((n) => CHAIN_RE.test(n));
    if (chainFiles.length > 1) problems.push(`${d}: ${chainFiles.length} chain receipts in one dir (ambiguous)`);
    for (const cf of chainFiles) {
      const full = join(ledgerDir, d, cf);
      const r = verifyFile(full, pinnedKey);
      if (!r.ok) problems.push(`${d}/${cf}: link receipt fails verification: ${r.fails.join('; ')}`);
      let body = null;
      try { body = JSON.parse(Buffer.from(JSON.parse(readFileSync(full, 'utf8')).payload, 'base64').toString('utf8'))?.predicate?.summary ?? null; } catch { /* handled below */ }
      if (!body || !Number.isInteger(body.seq)) { problems.push(`${d}/${cf}: unreadable chain body`); continue; }
      links.push({ dir: d, file: cf, body, sha256: sha256Hex(readFileSync(full)) });
    }
  }
  if (links.length === 0) { console.log('CHAIN FAIL: no chain receipts found under ' + ledgerDir); return false; }
  links.sort((a, b) => a.body.seq - b.body.seq);
  links.forEach((l, i) => { if (l.body.seq !== i + 1) problems.push(`seq not contiguous: expected ${i + 1}, found ${l.body.seq} (${l.dir}/${l.file})`); });
  if (links[0] && links[0].body.prev !== null) problems.push(`first link (${links[0].dir}/${links[0].file}) is not genesis: prev ≠ null`);
  for (let i = 1; i < links.length; i++) {
    const prev = links[i].body.prev;
    if (!prev) { problems.push(`seq ${links[i].body.seq}: missing prev pointer`); continue; }
    if (prev.sha256 !== links[i - 1].sha256 || prev.file !== links[i - 1].file || prev.runDir !== links[i - 1].dir) {
      problems.push(`seq ${links[i].body.seq}: prev pointer mismatch — chain BROKEN between ${links[i - 1].dir} and ${links[i].dir}`);
    }
  }
  const covered = new Map();
  for (const l of links) {
    for (const cov of l.body.covers ?? []) {
      if (covered.has(cov.dir)) problems.push(`dir ${cov.dir} sealed twice (seq ${covered.get(cov.dir).seq} and ${l.body.seq})`);
      else covered.set(cov.dir, { files: cov.files ?? [], seq: l.body.seq });
    }
  }
  for (const d of dirs) if (!covered.has(d)) problems.push(`dir ${d} NOT sealed by any chain link`);
  for (const [d, cov] of covered) {
    if (!dirs.includes(d)) { problems.push(`sealed dir ${d} MISSING from ledger (deleted after sealing)`); continue; }
    const onDisk = dirFiles[d];
    const listed = cov.files.map((f) => f.name).sort();
    if (JSON.stringify(onDisk) !== JSON.stringify(listed)) problems.push(`dir ${d}: file set mismatch — on disk [${onDisk.join(', ')}] vs sealed [${listed.join(', ')}]`);
    for (const f of cov.files) {
      if (!onDisk.includes(f.name)) continue;
      if (sha256Hex(readFileSync(join(ledgerDir, d, f.name))) !== f.sha256) problems.push(`${d}/${f.name}: sha256 mismatch — file REWRITTEN after sealing`);
    }
  }
  for (const p of problems) console.log(`      CHAIN FAIL: ${p}`);
  const head = links[links.length - 1];
  if (problems.length === 0) {
    console.log(`CHAIN OK  links=${links.length}  head=seq ${head.body.seq} sha256=${head.sha256.slice(0, 12)}…  dirs sealed=${covered.size}  files sealed=${[...covered.values()].reduce((a, c) => a + c.files.length, 0)}`);
    console.log('      note: honest limit — wholesale deletion of the newest link(s) needs external witnesses (Actions logs, INDEX git history)');
    return true;
  }
  console.log('CHAIN BROKEN');
  return false;
}

// ---- book replay (self-contained; reimplements the frozen v1 book rules) ----
const BOOK_RE = /^book_\d+\.receipt\.json$/;
const MICRO_B = 1_000_000n;
const QTY_B = 1_000_000_000n;

function toMicroB(x) {
  if (!Number.isFinite(x)) throw new Error('non-finite amount');
  const s = x.toFixed(6);
  const neg = s.startsWith('-');
  const [ints, fracs] = (neg ? s.slice(1) : s).split('.');
  const v = BigInt(ints) * MICRO_B + BigInt(fracs);
  return neg ? -v : v;
}
function microStrB(m) {
  const neg = m < 0n;
  const a = neg ? -m : m;
  return `${neg ? '-' : ''}${a / MICRO_B}.${(a % MICRO_B).toString().padStart(6, '0')}`;
}
function decisionFromStatement(file, st) {
  const dec = st?.predicate?.decision;
  if (!dec?.asset?.symbol || !dec.proposedAction || !dec.verdict) return null;
  return { file, symbol: dec.asset.symbol, proposedAction: dec.proposedAction, verdict: dec.verdict, priceUsd: dec.snapshot?.priceUsd ?? null, observedAtIso: dec.snapshot?.observedAtIso ?? null };
}

/** Byte-exact mirror of the engine's frozen v1 transition (portfolio math included). */
function replayTransition({ startState, config, decisions, generatedAtIso }) {
  const costRate = (config.costModel.feeBps + config.costModel.slippageBps) / 10_000;
  const book = { cashMicro: startState.cashMicro, positions: {}, fills: [] };
  for (const [a, p] of Object.entries(startState.positions)) book.positions[a] = { qtyE9: p.qtyE9, costMicro: p.costMicro };
  const sorted = [...decisions].sort((a, b) => (a.symbol < b.symbol ? -1 : a.symbol > b.symbol ? 1 : 0));
  const prices = {};
  for (const d of sorted) if (d.priceUsd > 0) prices[d.symbol] = d.priceUsd;
  const equityNow = () => {
    let eq = book.cashMicro;
    for (const [asset, p] of Object.entries(book.positions)) {
      if (p.qtyE9 === 0n) continue;
      const price = prices[asset];
      if (!(price > 0)) return null;
      eq += (p.qtyE9 * toMicroB(price)) / QTY_B;
    }
    return eq;
  };
  const noActions = [];
  for (const d of sorted) {
    const pos = book.positions[d.symbol];
    const held = !!pos && pos.qtyE9 > 0n;
    if (d.verdict !== 'ALLOWED') { noActions.push({ asset: d.symbol, action: 'NONE', why: `decision ${d.verdict} — fail closed, the gates hold the book` }); continue; }
    if (d.proposedAction === 'ENTER_LONG') {
      if (held) { noActions.push({ asset: d.symbol, action: 'NONE', why: 'already long — no pyramiding in v1' }); continue; }
      if (!(d.priceUsd > 0)) { noActions.push({ asset: d.symbol, action: 'NONE', why: 'no observed price — cannot fill honestly (fail closed)' }); continue; }
      const eq = equityNow();
      if (eq === null) { noActions.push({ asset: d.symbol, action: 'NONE', why: 'an open position is unpriced — equity not computable, no new entries (fail closed)' }); continue; }
      const allocMicro = (eq * BigInt(config.entryFractionBps)) / 10_000n;
      if (allocMicro <= 0n || allocMicro > book.cashMicro) { noActions.push({ asset: d.symbol, action: 'SKIPPED_INSUFFICIENT_CASH', why: `entry needs ${microStrB(allocMicro)} USD but paper cash is ${microStrB(book.cashMicro)} — no leverage, honest skip` }); continue; }
      const price = d.priceUsd;
      const notionalMicro = toMicroB(Number(microStrB(allocMicro)));
      const effPrice = price * (1 + costRate);
      const qtyE9 = (notionalMicro * QTY_B) / toMicroB(effPrice);
      const grossQtyE9 = (notionalMicro * QTY_B) / toMicroB(price);
      const modeledCostMicro = ((grossQtyE9 - qtyE9) * toMicroB(price)) / QTY_B;
      const cur = book.positions[d.symbol] ?? { qtyE9: 0n, costMicro: 0n };
      book.cashMicro -= notionalMicro;
      cur.qtyE9 += qtyE9;
      cur.costMicro += notionalMicro;
      book.positions[d.symbol] = cur;
      book.fills.push({ asset: d.symbol, side: 'BUY', notionalUsd: microStrB(notionalMicro), price: String(price), effectivePrice: effPrice.toFixed(10), qtyE9: qtyE9.toString(), modeledCostUsd: microStrB(modeledCostMicro), costModel: { feeBps: config.costModel.feeBps, slippageBps: config.costModel.slippageBps, label: 'MODELED' }, atIso: d.observedAtIso, reason: 'ALLOWED ENTER_LONG' });
    } else if (d.proposedAction === 'EXIT_LONG') {
      if (!held) { noActions.push({ asset: d.symbol, action: 'NONE', why: 'no open position to exit' }); continue; }
      if (!(d.priceUsd > 0)) { noActions.push({ asset: d.symbol, action: 'NONE', why: 'no observed price — cannot exit honestly (fail closed, position remains)' }); continue; }
      const price = d.priceUsd;
      const q = book.positions[d.symbol].qtyE9;
      const effPrice = price * (1 - costRate);
      const proceedsMicro = (q * toMicroB(effPrice)) / QTY_B;
      const grossMicro = (q * toMicroB(price)) / QTY_B;
      book.cashMicro += proceedsMicro;
      book.positions[d.symbol].qtyE9 -= q;
      if (book.positions[d.symbol].qtyE9 === 0n) book.positions[d.symbol].costMicro = 0n;
      book.fills.push({ asset: d.symbol, side: 'SELL', notionalUsd: microStrB(proceedsMicro), price: String(price), effectivePrice: effPrice.toFixed(10), qtyE9: q.toString(), modeledCostUsd: microStrB(grossMicro - proceedsMicro), costModel: { feeBps: config.costModel.feeBps, slippageBps: config.costModel.slippageBps, label: 'MODELED' }, atIso: d.observedAtIso, reason: 'ALLOWED EXIT_LONG' });
    } else {
      noActions.push({ asset: d.symbol, action: 'NONE', why: `${d.proposedAction} — no book action` });
    }
  }
  // mark-to-market (mirror)
  const positionsOut = [];
  let equityMicro = book.cashMicro;
  let unpriced = 0;
  for (const [asset, pos] of Object.entries(book.positions)) {
    if (pos.qtyE9 === 0n) continue;
    const p = prices[asset];
    if (!(p > 0)) { positionsOut.push({ asset, qtyE9: pos.qtyE9.toString(), value: { label: 'UNAVAILABLE', note: 'no observed price at mark time' } }); unpriced++; continue; }
    const valueMicro = (pos.qtyE9 * toMicroB(p)) / QTY_B;
    equityMicro += valueMicro;
    positionsOut.push({ asset, qtyE9: pos.qtyE9.toString(), markPrice: String(p), valueUsd: microStrB(valueMicro) });
  }
  const mark = {
    atIso: generatedAtIso,
    cashUsd: microStrB(book.cashMicro),
    positions: positionsOut,
    equityUsd: unpriced === 0 ? microStrB(equityMicro) : null,
    equityNote: unpriced === 0 ? undefined : `${unpriced} position(s) unpriced — equity not computable (honest empty)`,
    fillsSoFar: book.fills.length,
  };
  const statePositions = {};
  for (const [asset, p] of Object.entries(book.positions)) {
    if (p.qtyE9 > 0n) statePositions[asset] = { qtyE9: p.qtyE9.toString(), costMicro: p.costMicro.toString() };
  }
  return { fills: book.fills, noActions, state: { cashMicro: book.cashMicro.toString(), positions: statePositions }, mark, sortedDecisions: sorted };
}

function verifyBook(ledgerDir, pinnedKey) {
  let dirs;
  try {
    dirs = readdirSync(ledgerDir, { withFileTypes: true }).filter((e) => e.isDirectory()).map((e) => e.name).sort();
  } catch (e) { console.log(`BOOK FAIL: cannot read ${ledgerDir}: ${e.message}`); return false; }
  const problems = [];
  const links = [];
  for (const d of dirs) {
    const names = readdirSync(join(ledgerDir, d), { withFileTypes: true }).filter((e) => e.isFile()).map((e) => e.name).sort();
    const bookFiles = names.filter((n) => BOOK_RE.test(n));
    if (bookFiles.length > 1) problems.push(`${d}: ${bookFiles.length} book receipts in one dir (ambiguous)`);
    for (const bf of bookFiles) {
      const full = join(ledgerDir, d, bf);
      const r = verifyFile(full, pinnedKey);
      if (!r.ok) problems.push(`${d}/${bf}: book receipt fails verification: ${r.fails.join('; ')}`);
      let body = null;
      try { body = JSON.parse(Buffer.from(JSON.parse(readFileSync(full, 'utf8')).payload, 'base64').toString('utf8'))?.predicate?.summary ?? null; } catch { /* handled below */ }
      if (!body || !Number.isInteger(body.seq)) { problems.push(`${d}/${bf}: unreadable book body`); continue; }
      links.push({ dir: d, file: bf, body, sha256: sha256Hex(readFileSync(full)) });
    }
  }
  if (links.length === 0) { console.log('BOOK FAIL: no book receipts found under ' + ledgerDir); return false; }
  links.sort((a, b) => a.body.seq - b.body.seq);
  links.forEach((l, i) => { if (l.body.seq !== i + 1) problems.push(`seq not contiguous: expected ${i + 1}, found ${l.body.seq} (${l.dir}/${l.file})`); });
  if (links[0] && links[0].body.prev !== null) problems.push(`first book (${links[0].dir}/${links[0].file}) is not genesis: prev ≠ null`);
  for (const l of links) if (l.body.runDir !== l.dir) problems.push(`seq ${l.body.seq}: body.runDir ${l.body.runDir} ≠ actual dir ${l.dir}`);
  for (let i = 1; i < links.length; i++) {
    const prev = links[i].body.prev;
    if (!prev) { problems.push(`seq ${links[i].body.seq}: missing prev pointer`); continue; }
    if (prev.sha256 !== links[i - 1].sha256 || prev.file !== links[i - 1].file || prev.runDir !== links[i - 1].dir) {
      problems.push(`seq ${links[i].body.seq}: prev pointer mismatch — book chain BROKEN between ${links[i - 1].dir} and ${links[i].dir}`);
    }
    if (!(links[i].dir > links[i - 1].dir)) problems.push(`seq ${links[i].body.seq}: run dir ${links[i].dir} not after ${links[i - 1].dir}`);
    if (canonicalize(links[i].body.config) !== canonicalize(links[i - 1].body.config)) problems.push(`seq ${links[i].body.seq}: config drifted from previous link (must be inherited unchanged)`);
  }
  // Declared gap honesty: pre-book and skipped dirs must match the disk exactly.
  if (links[0]) {
    const expectPre = dirs.filter((d) => d < links[0].dir);
    if (canonicalize(links[0].body.preBookRunDirs ?? null) !== canonicalize(expectPre)) problems.push(`genesis preBookRunDirs do not match the ledger (expected [${expectPre.join(', ')}])`);
  }
  for (let i = 1; i < links.length; i++) {
    const expectSkip = dirs.filter((d) => d > links[i - 1].dir && d < links[i].dir);
    if (canonicalize(links[i].body.skippedRunDirs ?? null) !== canonicalize(expectSkip)) problems.push(`seq ${links[i].body.seq}: skippedRunDirs do not match the ledger (expected [${expectSkip.join(', ')}])`);
  }
  // REPLAY each link from the signed signal receipts on disk.
  for (let i = 0; i < links.length; i++) {
    const l = links[i];
    const cfg = l.body.config;
    if (!cfg?.costModel || !Number.isFinite(cfg.costModel.feeBps) || !Number.isFinite(cfg.costModel.slippageBps) || !Number.isFinite(cfg.entryFractionBps) || !(cfg.startingCashUsd > 0)) {
      problems.push(`seq ${l.body.seq}: config incomplete — cannot replay`); continue;
    }
    if (!dirs.includes(l.dir)) { problems.push(`seq ${l.body.seq}: run dir ${l.dir} missing from ledger`); continue; }
    const sigNames = readdirSync(join(ledgerDir, l.dir), { withFileTypes: true }).filter((e) => e.isFile()).map((e) => e.name).filter((n) => n.startsWith('signal_') && n.endsWith('.receipt.json')).sort();
    const decisions = [];
    const excludedFiles = [];
    for (const n of sigNames) {
      const r = verifyFile(join(ledgerDir, l.dir, n), pinnedKey);
      if (!r.ok) { excludedFiles.push(n); continue; }
      let st = null;
      try { st = JSON.parse(Buffer.from(JSON.parse(readFileSync(join(ledgerDir, l.dir, n), 'utf8')).payload, 'base64').toString('utf8')); } catch { excludedFiles.push(n); continue; }
      const dec = decisionFromStatement(n, st);
      if (dec) decisions.push(dec);
    }
    const startState = l.body.seq === 1
      ? { cashMicro: toMicroB(cfg.startingCashUsd), positions: {} }
      : (() => {
          const prevBody = links[i - 1].body;
          const positions = {};
          for (const [a, p] of Object.entries(prevBody.state?.positions ?? {})) positions[a] = { qtyE9: BigInt(p.qtyE9), costMicro: BigInt(p.costMicro) };
          return { cashMicro: BigInt(prevBody.state.cashMicro), positions };
        })();
    let rep;
    try { rep = replayTransition({ startState, config: cfg, decisions, generatedAtIso: l.body.generatedAtIso }); }
    catch (e) { problems.push(`seq ${l.body.seq}: replay threw — ${e.message}`); continue; }
    const expectInputs = {
      signalFiles: rep.sortedDecisions.map((d) => d.file).sort(),
      decisions: rep.sortedDecisions.map(({ file, symbol, proposedAction, verdict, priceUsd, observedAtIso }) => ({ file, symbol, proposedAction, verdict, priceUsd, observedAtIso })),
      excludedSignals: { count: excludedFiles.length, files: [...excludedFiles].sort() },
    };
    if (canonicalize(l.body.inputs ?? null) !== canonicalize(expectInputs)) problems.push(`seq ${l.body.seq}: inputs do not match the verified signal receipts on disk — book misrepresents its inputs`);
    if (canonicalize(l.body.fills ?? null) !== canonicalize(rep.fills)) problems.push(`seq ${l.body.seq}: fills do not REPLAY from the signed decisions (recomputed fills differ)`);
    if (canonicalize(l.body.noActions ?? null) !== canonicalize(rep.noActions)) problems.push(`seq ${l.body.seq}: noActions do not replay (fail-closed notes differ)`);
    if (canonicalize(l.body.state ?? null) !== canonicalize(rep.state)) problems.push(`seq ${l.body.seq}: end state does not replay — cash/positions REWRITTEN or miscomputed`);
    if (canonicalize(l.body.mark ?? null) !== canonicalize(rep.mark)) problems.push(`seq ${l.body.seq}: mark-to-market does not replay — equity cannot be trusted`);
  }
  for (const p of problems) console.log(`      BOOK FAIL: ${p}`);
  const head = links[links.length - 1];
  if (problems.length === 0) {
    const eq = head.body.mark?.equityUsd;
    const usd = (v) => '\u0024' + v; // literal dollar sign, kept as escape to survive tooling
    console.log(`BOOK OK  links=${links.length}  head=seq ${head.body.seq}  equity=${eq === null || eq === undefined ? 'UNAVAILABLE (honest empty)' : usd(eq)} [MODELED]  open=${(head.body.mark?.positions ?? []).length}  cash=${usd(head.body.mark?.cashUsd)}`);
    console.log('      note: every fill, state and mark recomputed from DSSE-verified signal receipts alone — paper simulation, NOT real funds');
    return true;
  }
  console.log('BOOK BROKEN');
  return false;
}

// ---- refusal record (self-contained mirror of src/refusals.mjs rules) ----
const REFUSALS_RE = /^refusals_\d+\.receipt\.json$/;

function refusalsDecisionMirror(file, st) {
  const dec = st?.predicate?.decision;
  if (!dec?.asset?.symbol || !dec.proposedAction || !dec.verdict) return null;
  return {
    file,
    symbol: dec.asset.symbol,
    verdict: dec.verdict,
    proposedAction: dec.proposedAction,
    conviction: typeof dec.conviction === 'number' ? dec.conviction : null,
    blockedBy: Array.isArray(dec.blockedBy) ? [...dec.blockedBy].sort() : [],
  };
}

function refusalsCensusMirror(decisions, excludedFiles) {
  const sorted = [...decisions].sort((a, b) => (a.symbol < b.symbol ? -1 : a.symbol > b.symbol ? 1 : 0));
  const byAction = {};
  const gateCounts = {};
  let allowed = 0;
  let blocked = 0;
  for (const d of sorted) {
    byAction[d.proposedAction] = (byAction[d.proposedAction] ?? 0) + 1;
    if (d.verdict === 'ALLOWED') allowed++;
    else blocked++;
    for (const g of d.blockedBy) gateCounts[g] = (gateCounts[g] ?? 0) + 1;
  }
  const refusalsByGate = Object.entries(gateCounts).sort(([a], [b]) => (a < b ? -1 : 1)).map(([gate, count]) => ({ gate, count }));
  return {
    inputs: { signalFiles: sorted.map((d) => d.file).sort(), excludedSignals: { count: excludedFiles.length, files: [...excludedFiles].sort() } },
    decisions: sorted,
    totals: { decisions: sorted.length, allowed, blocked, byAction, refusalsByGate },
  };
}

function verifyRefusals(ledgerDir, pinnedKey) {
  let dirs;
  try {
    dirs = readdirSync(ledgerDir, { withFileTypes: true }).filter((e) => e.isDirectory()).map((e) => e.name).sort();
  } catch (e) { console.log(`REFUSALS FAIL: cannot read ${ledgerDir}: ${e.message}`); return false; }
  const problems = [];
  const recs = [];
  for (const d of dirs) {
    const names = readdirSync(join(ledgerDir, d), { withFileTypes: true }).filter((e) => e.isFile()).map((e) => e.name).sort();
    const rfs = names.filter((n) => REFUSALS_RE.test(n));
    if (rfs.length > 1) problems.push(`${d}: ${rfs.length} refusal records in one dir (ambiguous)`);
    for (const rf of rfs) {
      const full = join(ledgerDir, d, rf);
      const r = verifyFile(full, pinnedKey);
      if (!r.ok) problems.push(`${d}/${rf}: refusal record fails verification: ${r.fails.join('; ')}`);
      let body = null;
      try { body = JSON.parse(Buffer.from(JSON.parse(readFileSync(full, 'utf8')).payload, 'base64').toString('utf8'))?.predicate?.summary ?? null; } catch { /* handled below */ }
      if (!body || body.kind !== 'szl-quant-refusals') { problems.push(`${d}/${rf}: unreadable refusal record body`); continue; }
      if (body.runDir !== d) problems.push(`${d}/${rf}: body.runDir ${body.runDir} \u2260 actual dir ${d}`);
      recs.push({ dir: d, file: rf, body });
    }
  }
  if (recs.length === 0) { console.log('REFUSALS FAIL: no refusal records found under ' + ledgerDir); return false; }
  // REPLAY each census from the signed decision receipts on disk.
  for (const rec of recs) {
    const sigNames = readdirSync(join(ledgerDir, rec.dir), { withFileTypes: true }).filter((e) => e.isFile()).map((e) => e.name).filter((n) => n.startsWith('signal_') && n.endsWith('.receipt.json')).sort();
    const decisions = [];
    const excludedFiles = [];
    for (const n of sigNames) {
      const r = verifyFile(join(ledgerDir, rec.dir, n), pinnedKey);
      if (!r.ok) { excludedFiles.push(n); continue; }
      let st = null;
      try { st = JSON.parse(Buffer.from(JSON.parse(readFileSync(join(ledgerDir, rec.dir, n), 'utf8')).payload, 'base64').toString('utf8')); } catch { excludedFiles.push(n); continue; }
      const dec = refusalsDecisionMirror(n, st);
      if (dec) decisions.push(dec);
    }
    const expect = refusalsCensusMirror(decisions, excludedFiles);
    if (canonicalize(rec.body.inputs ?? null) !== canonicalize(expect.inputs)) problems.push(`${rec.dir}: inputs do not match the verified signal receipts on disk`);
    if (canonicalize(rec.body.decisions ?? null) !== canonicalize(expect.decisions)) problems.push(`${rec.dir}: decision census does not REPLAY from the signed receipts`);
    if (canonicalize(rec.body.totals ?? null) !== canonicalize(expect.totals)) problems.push(`${rec.dir}: totals do not replay — refusal counts cannot be trusted`);
  }
  for (const p of problems) console.log(`      REFUSALS FAIL: ${p}`);
  if (problems.length === 0) {
    const h = recs[recs.length - 1].body;
    const gates = [...(h.totals.refusalsByGate ?? [])].sort((a, b) => b.count - a.count).map((x) => `${x.gate}\u00d7${x.count}`).join(' ');
    console.log(`REFUSALS OK  records=${recs.length}  latest ${h.runDir}: BLOCKED ${h.totals.blocked}/${h.totals.decisions}${gates ? `  by gate: ${gates}` : ''} [MEASURED]`);
    console.log('      note: every count recomputed from DSSE-verified decision receipts alone — a refusal is a decision, not an absence');
    return true;
  }
  console.log('REFUSALS BROKEN');
  return false;
}

// ---- external witness (self-contained mirror of src/witness.mjs rules) ----
const WITNESS_RE = /^witness_\d{4}_\d+\.receipt\.json$/;
const CHAINFILE_RE = /^chain_(\d{4})\.receipt\.json$/;

function rekordFieldsMirror(entryBodyBase64) {
  let e;
  try { e = JSON.parse(Buffer.from(entryBodyBase64, 'base64').toString('utf8')); } catch { return null; }
  if (e?.kind !== 'rekord') return null;
  const hash = e.spec?.data?.hash;
  const sig = e.spec?.signature;
  if (hash?.algorithm !== 'sha256' || !hash?.value || !sig?.content || !sig?.publicKey?.content) return null;
  return { dataSha256: hash.value, signatureBase64: sig.content, publicKeyPemBase64: sig.publicKey.content };
}

// ---- external witness: RFC 6962 inclusion mirrors (self-contained on purpose —
// this verifier audits the engine and must not trust its code) ----
function rfcLeafMirror(bytes) { return createHash('sha256').update(Buffer.concat([Buffer.from([0x00]), bytes])).digest(); }
function rfcNodeMirror(l, r) { return createHash('sha256').update(Buffer.concat([Buffer.from([0x01]), l, r])).digest(); }
function rfcRootMirror(leafIndex, treeSize, leafHash, hashesHex) {
  if (!Number.isInteger(leafIndex) || !Number.isInteger(treeSize) || leafIndex < 0 || treeSize < 1 || leafIndex >= treeSize) throw new Error(`leaf index ${leafIndex} outside tree of size ${treeSize}`);
  const path = (hashesHex ?? []).map((h) => { const b = Buffer.from(String(h), 'hex'); if (b.length !== 32) throw new Error('sibling hash is not 32 bytes'); return b; });
  let h = leafHash;
  let idx = leafIndex;
  let last = treeSize - 1;
  let used = 0;
  while (last > 0) {
    if (idx % 2 === 1) { if (used >= path.length) throw new Error('audit path too short'); h = rfcNodeMirror(path[used++], h); }
    else if (idx < last) { if (used >= path.length) throw new Error('audit path too short'); h = rfcNodeMirror(h, path[used++]); }
    idx = Math.floor(idx / 2);
    last = Math.floor(last / 2);
  }
  if (used !== path.length) throw new Error(`${path.length - used} unconsumed sibling hash(es)`);
  return h;
}
/** Verify a Rekor checkpoint (signed note) against the pinned rekor key.
 *  The 4-byte key hint must match sha256(SPKI)[0..4] AND the ECDSA
 *  signature must verify over the exact note body. */
function checkpointMirror(text, rekorPub) {
  const sep = typeof text === 'string' ? text.indexOf('\n\n') : -1;
  if (sep < 0) return { ok: false, reason: 'checkpoint has no blank-line separator' };
  const noteBody = text.slice(0, sep + 1);
  const lines = noteBody.split('\n');
  if (lines.length < 4 || !/^\S+ - \d+$/.test(lines[0]) || !/^\d+$/.test(lines[1])) return { ok: false, reason: 'checkpoint note malformed' };
  const treeSize = Number(lines[1]);
  const root = Buffer.from(lines[2], 'base64');
  if (!Number.isSafeInteger(treeSize) || treeSize < 1 || root.length !== 32 || root.toString('base64') !== lines[2]) return { ok: false, reason: 'checkpoint tree size or root hash malformed' };
  const hint = createHash('sha256').update(rekorPub.export({ type: 'spki', format: 'der' })).digest().slice(0, 4).toString('hex');
  let sawHint = false;
  for (const line of text.slice(sep + 2).split('\n')) {
    if (!line) continue;
    const m = line.match(/^\u2014 \S+ (\S+)$/);
    if (!m) continue;
    const raw = Buffer.from(m[1], 'base64');
    if (raw.length < 5 || raw.slice(0, 4).toString('hex') !== hint) continue;
    sawHint = true;
    try { if (edVerify('sha256', Buffer.from(noteBody, 'utf8'), rekorPub, raw.slice(4))) return { ok: true, treeSize, rootHashHex: root.toString('hex'), origin: lines[0] }; } catch { /* fail closed below */ }
  }
  return { ok: false, reason: sawHint ? 'checkpoint signature INVALID over the signed note' : 'no checkpoint signature carries the pinned rekor key hint' };
}

const CONS_RE = /^consistency_\d+-\d+_\d+\.receipt\.json$/;

// RFC 6962 (2.1.4.2) consistency verification, self-contained mirror —
// proves the tree at firstSize is a PREFIX of the tree at secondSize.
// Sizes exceed 2^31 eventually: no 32-bit bitwise ops, only % and floor.
function rfcConsistencyMirror(firstSize, secondSize, firstRootHex, secondRootHex, hashesHex) {
  if (!Number.isSafeInteger(firstSize) || !Number.isSafeInteger(secondSize) || firstSize < 1 || secondSize < firstSize) throw new Error(`consistency proof rejected: invalid tree sizes ${firstSize} -> ${secondSize}`);
  const first = Buffer.from(String(firstRootHex), 'hex');
  const second = Buffer.from(String(secondRootHex), 'hex');
  if (first.length !== 32 || second.length !== 32) throw new Error('consistency proof rejected: root hash is not 32 bytes');
  const proof = (hashesHex ?? []).map((h) => { const b = Buffer.from(String(h), 'hex'); if (b.length !== 32) throw new Error('consistency proof rejected: proof hash is not 32 bytes'); return b; });
  if (firstSize === secondSize) {
    if (proof.length !== 0) throw new Error('consistency proof rejected: same-size proof must be empty');
    if (!first.equals(second)) throw new Error('consistency proof rejected: same tree size but DIFFERENT roots — split-view evidence');
    return;
  }
  let isPow2 = true; { let n = firstSize; while (n % 2 === 0 && n > 1) n /= 2; isPow2 = n === 1; }
  const items = isPow2 ? [first, ...proof] : proof;
  if (items.length === 0) throw new Error('consistency proof rejected: empty proof for a grown tree');
  let fn = firstSize - 1;
  let sn = secondSize - 1;
  while (fn % 2 === 1) { fn = Math.floor(fn / 2); sn = Math.floor(sn / 2); }
  let fr = items[0];
  let sr = items[0];
  for (let i = 1; i < items.length; i++) {
    if (sn === 0) throw new Error('consistency proof rejected: too many proof hashes');
    if (fn % 2 === 1 || fn === sn) {
      fr = rfcNodeMirror(items[i], fr);
      sr = rfcNodeMirror(items[i], sr);
      while (fn % 2 === 0 && fn !== 0) { fn = Math.floor(fn / 2); sn = Math.floor(sn / 2); }
    } else {
      sr = rfcNodeMirror(sr, items[i]);
    }
    fn = Math.floor(fn / 2);
    sn = Math.floor(sn / 2);
  }
  if (!fr.equals(first)) throw new Error('consistency proof rejected: recomputed OLD root differs — the earlier checkpoint is not a prefix of the later tree');
  if (!sr.equals(second)) throw new Error('consistency proof rejected: recomputed NEW root differs — proof does not land on the later signed root');
  if (sn !== 0) throw new Error('consistency proof rejected: proof hashes exhausted before reaching the root');
}

function verifyWitness(rootDir, pinnedKey, rekorPubPath) {
  if (!pinnedKey) { console.log('WITNESS FAIL: --witness requires --pubkey (pinned engine key) — refusing TOFU here'); return false; }
  let rekorPub;
  try { rekorPub = createPublicKey(readFileSync(rekorPubPath, 'utf8')); }
  catch (e) { console.log(`WITNESS FAIL: cannot load pinned rekor pubkey ${rekorPubPath}: ${e.message}`); return false; }
  const wDir = join(rootDir, 'witness');
  const lDir = join(rootDir, 'ledger');
  let names = [];
  try { names = readdirSync(wDir, { withFileTypes: true }).filter((e) => e.isFile()).map((e) => e.name).filter((n) => WITNESS_RE.test(n)).sort(); } catch { /* absent dir handled below */ }
  if (names.length === 0) { console.log('WITNESS FAIL: no witness receipts under ' + wDir); return false; }
  const problems = [];
  const anchoredSeqs = new Set();
  const provenSeqs = new Set();
  let setOnly = 0;
  const cps = []; // verified checkpoints: raw material for the consistency chain
  let latest = null;
  for (const n of names) {
    const full = join(wDir, n);
    const r = verifyFile(full, pinnedKey);
    if (!r.ok) { problems.push(`${n}: DSSE verification failed: ${r.fails.join('; ')}`); continue; }
    let body = null;
    try { body = JSON.parse(Buffer.from(JSON.parse(readFileSync(full, 'utf8')).payload, 'base64').toString('utf8'))?.predicate?.summary ?? null; } catch { /* handled */ }
    if (!body || body.kind !== 'szl-quant-witness') { problems.push(`${n}: unreadable witness body`); continue; }
    // 1) the witnessed chain link must still exist on disk, byte-identical
    let cbytes = null;
    try { cbytes = readFileSync(join(lDir, body.chain.runDir, body.chain.file)); }
    catch { problems.push(`${n}: witnessed chain link ${body.chain.runDir}/${body.chain.file} MISSING from ledger — truncation evidence`); }
    if (!cbytes) continue;
    const sha = sha256Hex(cbytes);
    if (sha !== body.chain.sha256) problems.push(`${n}: chain link bytes CHANGED after witnessing (sha256 mismatch)`);
    // 2) the rekor entry must anchor exactly these bytes with the pinned engine key
    const f = rekordFieldsMirror(body.rekor?.entryBodyBase64 ?? '');
    if (!f) { problems.push(`${n}: rekor entry body unreadable or not a rekord entry`); continue; }
    if (f.dataSha256 !== sha) problems.push(`${n}: rekor entry anchors DIFFERENT bytes (hash mismatch)`);
    try {
      const entryPub = createPublicKey(Buffer.from(f.publicKeyPemBase64, 'base64').toString('utf8'));
      const samePin = entryPub.export({ type: 'spki', format: 'der' }).equals(pinnedKey.export({ type: 'spki', format: 'der' }));
      if (!samePin) problems.push(`${n}: rekor entry public key is NOT the pinned engine key`);
      if (!edVerify(null, cbytes, entryPub, Buffer.from(f.signatureBase64, 'base64'))) problems.push(`${n}: artifact signature in rekor entry INVALID over chain bytes`);
    } catch (e) { problems.push(`${n}: rekor entry public key unreadable: ${e.message}`); }
    // 3) SET: rekor's own signature over {body, integratedTime, logID, logIndex}
    try {
      const msg = Buffer.from(canonicalize({ body: body.rekor.entryBodyBase64, integratedTime: body.rekor.integratedTime, logID: body.rekor.logID, logIndex: body.rekor.logIndex }), 'utf8');
      if (!edVerify('sha256', msg, rekorPub, Buffer.from(body.rekor.signedEntryTimestampBase64, 'base64'))) {
        problems.push(`${n}: rekor SET INVALID — no offline proof rekor accepted this entry`);
      }
    } catch (e) { problems.push(`${n}: SET check failed: ${e.message}`); }
    // 4) Merkle inclusion (generation 2): the leaf recomputed from the entry
    // bytes must walk the audit path onto the checkpoint's SIGNED root.
    const ip = body.rekor?.inclusionProof;
    if (ip) {
      const cp = checkpointMirror(ip.checkpoint, rekorPub);
      if (!cp.ok) problems.push(`${n}: ${cp.reason}`);
      else if (cp.treeSize !== ip.treeSize) problems.push(`${n}: inclusion tree size mismatch (proof says ${ip.treeSize}, signed checkpoint says ${cp.treeSize})`);
      else if (cp.rootHashHex !== ip.rootHash) problems.push(`${n}: inclusion root mismatch — proof root differs from the signed checkpoint root`);
      else {
        try {
          const computed = rfcRootMirror(ip.logIndex, ip.treeSize, rfcLeafMirror(Buffer.from(body.rekor.entryBodyBase64, 'base64')), ip.hashes);
          if (!computed.equals(Buffer.from(cp.rootHashHex, 'hex'))) problems.push(`${n}: audit path does NOT land on the signed root — entry not proven in this tree`);
          else {
            if (Number.isInteger(body.chain?.seq)) provenSeqs.add(body.chain.seq);
            cps.push({ file: n, fileSha: sha256Hex(readFileSync(full)), origin: cp.origin, treeSize: ip.treeSize, rootHashHex: ip.rootHash });
          }
        } catch (e) { problems.push(`${n}: inclusion proof rejected: ${e.message}`); }
      }
    } else {
      setOnly += 1; // generation-1 receipt: SET-only, and it SAYS so in its limits
    }
    if (Number.isInteger(body.chain?.seq)) {
      anchoredSeqs.add(body.chain.seq);
      if (!latest || body.chain.seq > latest.chain.seq) latest = body;
    }
  }
  // 5) generation 3 — checkpoint consistency: every adjacent pair of
  // captured checkpoints must chain append-only; two verified checkpoints
  // that disagree at the SAME tree size are split-view evidence.
  const bySizeKey = new Map();
  for (const c of cps) {
    const k = `${c.origin}|${c.treeSize}`;
    const seen = bySizeKey.get(k);
    if (seen && seen.rootHashHex !== c.rootHashHex) problems.push(`${c.file}: SPLIT-VIEW EVIDENCE — checkpoint at tree size ${c.treeSize} has a different root than ${seen.file}`);
    if (!seen) bySizeKey.set(k, c);
  }
  let consNames = [];
  try { consNames = readdirSync(wDir, { withFileTypes: true }).filter((e) => e.isFile()).map((e) => e.name).filter((n) => CONS_RE.test(n)).sort(); } catch { /* dir readable above */ }
  const cpsByFile = new Map(cps.map((c) => [c.file, c]));
  const verifiedEdges = new Set();
  for (const n of consNames) {
    const full = join(wDir, n);
    const r = verifyFile(full, pinnedKey);
    if (!r.ok) { problems.push(`${n}: DSSE verification failed: ${r.fails.join('; ')}`); continue; }
    let body = null;
    try { body = JSON.parse(Buffer.from(JSON.parse(readFileSync(full, 'utf8')).payload, 'base64').toString('utf8'))?.predicate?.summary ?? null; } catch { /* handled */ }
    if (!body || body.kind !== 'szl-quant-witness-consistency') { problems.push(`${n}: unreadable consistency body`); continue; }
    const pv = cpsByFile.get(body.prev?.receiptFile);
    const nx = cpsByFile.get(body.next?.receiptFile);
    if (!pv || !nx) { problems.push(`${n}: endpoint witness receipt(s) missing or unproven — a consistency link needs BOTH verified checkpoints`); continue; }
    if (pv.fileSha !== body.prev.receiptSha256 || nx.fileSha !== body.next.receiptSha256) { problems.push(`${n}: endpoint receipt bytes CHANGED after linking (sha256 mismatch)`); continue; }
    if (pv.origin !== body.origin || nx.origin !== body.origin) { problems.push(`${n}: origin mismatch between link and endpoint checkpoints`); continue; }
    if (pv.treeSize !== body.prev.treeSize || pv.rootHashHex !== body.prev.rootHash || nx.treeSize !== body.next.treeSize || nx.rootHashHex !== body.next.rootHash) { problems.push(`${n}: claimed endpoint sizes/roots differ from the verified checkpoints`); continue; }
    try {
      rfcConsistencyMirror(body.prev.treeSize, body.next.treeSize, body.prev.rootHash, body.next.rootHash, body.proofHashes);
      verifiedEdges.add(`${body.origin}|${body.prev.treeSize}|${body.next.treeSize}`);
    } catch (e) { problems.push(`${n}: ${e.message}`); }
  }
  let consEdges = 0;
  let consProven = 0;
  {
    const byOrigin = new Map();
    for (const c of cps) {
      if (!byOrigin.has(c.origin)) byOrigin.set(c.origin, new Set());
      byOrigin.get(c.origin).add(c.treeSize);
    }
    for (const [origin, sizesSet] of byOrigin) {
      const sizes = [...sizesSet].sort((a, b) => a - b);
      for (let i = 1; i < sizes.length; i++) {
        consEdges += 1;
        if (verifiedEdges.has(`${origin}|${sizes[i - 1]}|${sizes[i]}`)) consProven += 1;
      }
    }
  }
  // coverage vs. chain links actually present (gaps counted, not hidden)
  const linkSeqs = new Set();
  try {
    for (const d of readdirSync(lDir, { withFileTypes: true }).filter((e) => e.isDirectory()).map((e) => e.name)) {
      for (const f of readdirSync(join(lDir, d))) { const m = f.match(CHAINFILE_RE); if (m) linkSeqs.add(parseInt(m[1], 10)); }
    }
  } catch { /* ledger dir problems surface via --chain */ }
  for (const p of problems) console.log(`      WITNESS FAIL: ${p}`);
  if (problems.length === 0 && latest) {
    const t = new Date(latest.rekor.integratedTime * 1000).toISOString();
    const setOnlyNote = setOnly > 0 ? ` (${setOnly} SET-only receipt(s) — each states that limit itself)` : '';
    console.log(`WITNESS OK  anchors=${names.length}  heads anchored=${anchoredSeqs.size}/${linkSeqs.size} chain links  inclusion proven offline=${provenSeqs.size}/${linkSeqs.size}${setOnlyNote}  log consistency=${consProven}/${consEdges} adjacent checkpoint pair(s)  latest: seq ${latest.chain.seq} \u2192 rekor logIndex ${latest.rekor.logIndex} (integrated ${t}) [REPORTED, SET verified offline${provenSeqs.size > 0 ? ' + Merkle inclusion replayed offline' : ''}${consProven > 0 && consProven === consEdges ? ' + log consistency replayed offline' : ''}]`);
    console.log('      note: anchored heads live in a public append-only log — deleting this ledger does not delete the anchors; unwitnessed links are counted above, not hidden');
    if (consEdges > 0 && consProven === consEdges) console.log("      note: consistency replayed offline across every captured checkpoint — the log is proven append-only for this engine's whole observation window (second-observer gossip cross-checks below)");
    else if (consEdges > 0) console.log(`      note: consistency proven for ${consProven}/${consEdges} adjacent checkpoint pair(s) — unproven edges are counted, not hidden (second-observer gossip cross-checks below)`);
    else if (provenSeqs.size > 0) console.log('      note: inclusion is proven against the checkpoint captured at anchor time — checkpoint-to-checkpoint consistency is not verified offline');
    return true;
  }
  console.log('WITNESS BROKEN');
  return false;
}


// ═══ SECOND WITNESS (RFC 3161) MIRROR — self-contained copy of src/tsa.mjs ═══
// The verifier imports NOTHING from src/; keep this in sync with src/tsa.mjs
// by hand. Tokens are verified fully offline against repo-pinned anchors.

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


// ── DER primitives ─────────────────────────────────────────────────────────
function derNode(buf, off) {
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
function derChildren(buf, node) {
  const out = [];
  let off = node.start;
  while (off < node.end) { const c = derNode(buf, off); out.push(c); off = c.end; }
  return out;
}
function derOid(buf, node) {
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
function derSlice(buf, node) { return buf.subarray(node.header, node.end); } // full TLV
function derValue(buf, node) { return buf.subarray(node.start, node.end); }
function parseGeneralizedTime(s) {
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
function buildTimestampRequest(sha256hex, nonce) {
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
function parseTimestampResponse(respDer) {
  const root = derNode(respDer, 0);
  const kids = derChildren(respDer, root);
  const statusKids = derChildren(respDer, kids[0]);
  const status = respDer[statusKids[0].start]; // small INTEGER
  if (status !== 0 && status !== 1) throw new Error(`TSA: status ${status} — request not granted`);
  if (kids.length < 2) throw new Error('TSA: granted but no token present');
  return { status, tokenDer: Buffer.from(derSlice(respDer, kids[1])) };
}

function parseToken(tokenDer) {
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
function assertNonceEcho(expectedNonceHex, actualNonceHex) {
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
function verifyTimestampToken({ tokenDer, expectedImprintHex, anchors, expectedNonceHex = null, now = null }) {
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
const TSA_FILE_RE = /^tsa_(\d{4})_(\d+)\.receipt\.json$/;
const tsaFileName = (seq, ts) => `tsa_${String(seq).padStart(4, '0')}_${ts}.receipt.json`;
function buildTsaBody({ seq, witnessFile, witnessSha256, authority, verified, tokenDerBase64, nonceHex, backfilled, capturedAt }) {
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

function verifyTsa(rootDir, pinnedKey, anchorsDir) {
  if (!pinnedKey) { console.log('TSA FAIL: --witness requires --pubkey (pinned engine key) — refusing TOFU here'); return false; }
  const wDir = join(rootDir, 'witness');
  let all = [];
  try { all = readdirSync(wDir, { withFileTypes: true }).filter((e) => e.isFile()).map((e) => e.name); } catch { /* handled below */ }
  const tsaNames = all.filter((n) => TSA_FILE_RE.test(n)).sort();
  const headSeqs = new Set(all.filter((n) => WITNESS_RE.test(n)).map((n) => Number(/^witness_(\d{4})_/.exec(n)[1])));
  if (tsaNames.length === 0) {
    console.log(`TSA none  0/${headSeqs.size} head anchor(s) carry a second-witness timestamp — honest gap, the engine backfills on its next run`);
    return true; // absence is a counted gap, not corruption
  }
  let anchors = [];
  try { anchors = readdirSync(anchorsDir).filter((f) => f.endsWith('.pem')).sort().map((f) => readFileSync(join(anchorsDir, f), 'utf8')); } catch { /* handled below */ }
  if (anchors.length === 0) { console.log(`TSA FAIL: second-witness receipts exist but no pinned anchors under ${anchorsDir} — refusing to trust unpinned authorities`); return false; }
  const problems = [];
  const okSeqs = new Set();
  const authorities = new Set();
  for (const n of tsaNames) {
    const full = join(wDir, n);
    const r = verifyFile(full, pinnedKey);
    if (!r.ok) { problems.push(`${n}: DSSE verification failed: ${r.fails.join('; ')}`); continue; }
    let body = null;
    try { body = JSON.parse(Buffer.from(JSON.parse(readFileSync(full, 'utf8')).payload, 'base64').toString('utf8'))?.predicate?.summary ?? null; } catch { /* handled */ }
    if (!body || body.kind !== 'szl-quant-witness-tsa') { problems.push(`${n}: unreadable second-witness body`); continue; }
    if (body.seq !== Number(TSA_FILE_RE.exec(n)[1])) { problems.push(`${n}: body seq ${body.seq} does not match filename`); continue; }
    let wbytes = null;
    try { wbytes = readFileSync(join(wDir, body.witness.receiptFile)); }
    catch { problems.push(`${n}: timestamped witness receipt ${body.witness?.receiptFile} MISSING from ledger — truncation evidence`); continue; }
    const wsha = sha256Hex(wbytes);
    if (wsha !== body.witness.receiptSha256) { problems.push(`${n}: witness receipt bytes CHANGED after timestamping (sha256 mismatch)`); continue; }
    try {
      const v = verifyTimestampToken({
        tokenDer: Buffer.from(body.token.derBase64, 'base64'),
        expectedImprintHex: wsha,
        anchors,
        expectedNonceHex: body.token.nonceHex || null,
      });
      if (body.verifiedBeforeSigning?.genTime && v.genTime !== body.verifiedBeforeSigning.genTime) {
        problems.push(`${n}: receipt claims genTime ${body.verifiedBeforeSigning.genTime} but token says ${v.genTime}`);
        continue;
      }
      okSeqs.add(body.seq);
      authorities.add(body.authority?.name ?? 'unknown');
    } catch (e) { problems.push(`${n}: token FAILED offline verification: ${e.message}`); }
  }
  for (const p of problems) console.log(`      TSA FAIL: ${p}`);
  if (problems.length === 0) {
    console.log(`TSA OK  second witness countersigns ${okSeqs.size}/${headSeqs.size} head anchor(s)  authorities: ${[...authorities].sort().join(', ')}  [REPORTED, tokens verified offline against repo-pinned anchors]`);
    console.log('      note: an RFC 3161 authority with a DIFFERENT trust root than the transparency log vouches the receipt bytes existed no later than genTime — anchors are pin-on-first-use in keys/tsa/, not a WebPKI resolution');
    const missing = [...headSeqs].filter((s) => !okSeqs.has(s)).sort((a, b) => a - b);
    if (missing.length) console.log(`      note: uncovered head anchor seq(s) [${missing.join(', ')}] are counted, not hidden — the engine backfills on its next run`);
    return true;
  }
  console.log('TSA BROKEN');
  return false;
}

// ---- main ----

// ---- generation 5: cross-witness gossip (self-contained mirror) ----------
const OBS_RE = /^obs_(\d{4})_\d+\.observation\.json$/;
const GOSSIP_RE = /^gossip_(\d{4})_(\d+)\.receipt\.json$/;
const GOSSIP_PREDICATE_M = 'https://szl.holdings/quant/gossip-observation/v1';

/** Parse checkpoint note fields WITHOUT a signature check — used only for
 *  engine witness receipts whose notes verifyWitness already verified. */
function noteFieldsMirror(text) {
  const sep = text.indexOf('\n\n');
  const bodyLines = text.slice(0, sep + 1).split('\n');
  return { origin: bodyLines[0], treeSize: Number(bodyLines[1]), rootHashHex: Buffer.from(bodyLines[2], 'base64').toString('hex') };
}

function verifyGossip(rootDir, pinnedKey, rekorPubPath2, observerPubPath2) {
  const wDir = join(rootDir, 'witness');
  const gDir = join(wDir, 'gossip');
  let obsNames = [];
  try { obsNames = readdirSync(gDir).filter((n) => OBS_RE.test(n)).sort(); } catch { /* no gossip dir yet */ }
  let receiptNames = [];
  try { receiptNames = readdirSync(wDir).filter((n) => GOSSIP_RE.test(n)).sort(); } catch { /* no witness dir */ }
  if (!obsNames.length && !receiptNames.length) {
    console.log('\nGOSSIP  none — no second-observer observations archived yet (absence is honest)');
    return true;
  }
  const fails = [];
  let observerPub = null; let observerKeyId = null; let rekorPub = null;
  try {
    const pin = JSON.parse(readFileSync(observerPubPath2, 'utf8'));
    observerPub = createPublicKey({ key: Buffer.from(pin.publicKeySpkiBase64, 'base64'), type: 'spki', format: 'der' });
    observerKeyId = pin.keyId;
    if (sha256Hex(observerPub.export({ type: 'spki', format: 'der' })).slice(0, 16) !== pin.keyId) fails.push('observer pin keyId does not match its own key material');
  } catch (e) { fails.push(`cannot load observer pin ${observerPubPath2}: ${e.message} (refusing TOFU on a second-party key)`); }
  try { rekorPub = createPublicKey(readFileSync(rekorPubPath2, 'utf8')); } catch (e) { fails.push(`cannot load rekor pin ${rekorPubPath2}: ${e.message}`); }
  const liveCps = [];
  const censusActual = {};
  if (observerPub && rekorPub) {
    for (const n of obsNames) {
      try {
        const env = JSON.parse(readFileSync(join(gDir, n), 'utf8'));
        if (env.payloadType !== 'application/vnd.in-toto+json') { fails.push(`${n}: payloadType ${env.payloadType}`); continue; }
        const payloadBytes = Buffer.from(env.payload, 'base64');
        const sigEntry = (env.signatures ?? []).find((x) => x.keyid === observerKeyId);
        if (!sigEntry || !edVerify(null, pae(env.payloadType, payloadBytes), observerPub, Buffer.from(sigEntry.sig, 'base64'))) { fails.push(`${n}: observer ed25519 signature INVALID`); continue; }
        const st = JSON.parse(payloadBytes.toString('utf8'));
        const s = st.predicate?.summary;
        if (st.predicateType !== GOSSIP_PREDICATE_M || s?.kind !== 'szl-quant-gossip-observation') { fails.push(`${n}: wrong predicateType/kind`); continue; }
        if (s.label !== 'REPORTED') { fails.push(`${n}: label ${s.label} — observations must be REPORTED`); continue; }
        if (!Array.isArray(s.limits) || !s.limits.length) { fails.push(`${n}: states no limits — canon requires honesty about limits`); continue; }
        if (s.observer?.keyId !== observerKeyId || s.observer?.repo !== 'szl-holdings/szl-quant-witness') { fails.push(`${n}: observer identity mismatch`); continue; }
        if (st.subject?.[0]?.digest?.sha256 !== s.ledger?.witnessSha256) { fails.push(`${n}: subject does not bind the observed witness receipt`); continue; }
        let wBytes = null;
        try { wBytes = readFileSync(join(wDir, s.ledger.witnessFile)); } catch { fails.push(`${n}: observed witness receipt ${s.ledger.witnessFile} absent from this ledger`); continue; }
        if (sha256Hex(wBytes) !== s.ledger.witnessSha256) { fails.push(`${n}: witness receipt bytes DIFFER from what the observer saw — divergent-history evidence`); continue; }
        let chainSha = null;
        try { chainSha = sha256Hex(readFileSync(join(rootDir, 'ledger', s.ledger.chainRunDir, s.ledger.chainFile))); } catch { fails.push(`${n}: chain link ${s.ledger.chainFile} absent from this ledger`); continue; }
        if (chainSha !== s.ledger.chainSha256) { fails.push(`${n}: chain link bytes DIFFER from what the observer saw — divergent-history evidence`); continue; }
        const wSt = JSON.parse(Buffer.from(JSON.parse(wBytes.toString('utf8')).payload, 'base64').toString('utf8'));
        const eNote = wSt.predicate?.summary?.rekor?.inclusionProof?.checkpoint;
        if (!eNote) { fails.push(`${n}: local witness receipt carries no checkpoint`); continue; }
        const eCp = noteFieldsMirror(eNote);
        if (s.engineCheckpoint?.origin !== eCp.origin || s.engineCheckpoint?.treeSize !== eCp.treeSize || s.engineCheckpoint?.rootHex !== eCp.rootHashHex) { fails.push(`${n}: engineCheckpoint does not match the checkpoint inside the named witness receipt`); continue; }
        const lv = checkpointMirror(String(s.liveCheckpoint?.rawNote ?? ''), rekorPub);
        if (!lv.ok) { fails.push(`${n}: live checkpoint note failed offline verification (${lv.reason})`); continue; }
        if (lv.origin !== s.liveCheckpoint.origin || lv.treeSize !== s.liveCheckpoint.treeSize || lv.rootHashHex !== s.liveCheckpoint.rootHex) { fails.push(`${n}: liveCheckpoint fields do not match the embedded signed note`); continue; }
        let expected;
        if (eCp.origin !== lv.origin) expected = 'SHARD_ROTATED';
        else if (lv.treeSize < eCp.treeSize) expected = 'LOG_REGRESSED';
        else if (lv.treeSize === eCp.treeSize) expected = lv.rootHashHex === eCp.rootHashHex ? 'ROOTS_EQUAL' : 'SPLIT_VIEW';
        else {
          try { rfcConsistencyMirror(eCp.treeSize, lv.treeSize, eCp.rootHashHex, lv.rootHashHex, s.consistency?.proofHashes ?? []); expected = 'PREFIX_OK'; }
          catch { expected = 'SPLIT_VIEW'; }
        }
        const bindingAlarm = s.verdict === 'LEDGER_BINDING_MISMATCH' && s.ledger.chainBindingVerified === false && (expected === 'PREFIX_OK' || expected === 'ROOTS_EQUAL');
        if (s.verdict !== expected && !bindingAlarm) { fails.push(`${n}: signed verdict ${s.verdict} ≠ offline recomputation ${expected} — observers may not editorialize`); continue; }
        if (s.verdict !== 'PREFIX_OK' && s.verdict !== 'ROOTS_EQUAL') fails.push(`${n}: ALARMING verdict ${s.verdict} — signed split-view/binding evidence in the ledger`);
        censusActual[s.verdict] = (censusActual[s.verdict] ?? 0) + 1;
        liveCps.push({ origin: lv.origin, treeSize: lv.treeSize, rootHex: lv.rootHashHex, source: n });
      } catch (e) { fails.push(`${n}: ${e.message}`); }
    }
  }
  let newestReceipt = null;
  for (const n of receiptNames) {
    const r = verifyFile(join(wDir, n), pinnedKey);
    if (!r.ok) { fails.push(`${n}: ${r.fails.join('; ')}`); continue; }
    try {
      const s = JSON.parse(Buffer.from(JSON.parse(readFileSync(join(wDir, n), 'utf8')).payload, 'base64').toString('utf8')).predicate?.summary;
      if (s?.kind !== 'szl-quant-gossip-check' || s?.label !== 'REPORTED') { fails.push(`${n}: wrong kind/label for a gossip receipt`); continue; }
      if (!newestReceipt || s.generatedAtIso > newestReceipt.s.generatedAtIso) newestReceipt = { n, s };
    } catch (e) { fails.push(`${n}: ${e.message}`); }
  }
  if (receiptNames.length && !newestReceipt) fails.push('no valid engine-signed gossip receipt among those present');
  if (newestReceipt && newestReceipt.s.observations?.archivedTotal !== obsNames.length) {
    fails.push(`newest gossip receipt (${newestReceipt.n}) counts ${newestReceipt.s.observations?.archivedTotal} archived observation(s) but ${obsNames.length} are present`);
  }
  if (obsNames.length && !receiptNames.length) fails.push('observations archived but no engine-signed gossip receipt accounts for them');
  const cps = [...liveCps];
  try {
    for (const n of readdirSync(wDir).filter((x) => WITNESS_RE.test(x))) {
      try {
        const st = JSON.parse(Buffer.from(JSON.parse(readFileSync(join(wDir, n), 'utf8')).payload, 'base64').toString('utf8'));
        const note = st.predicate?.summary?.rekor?.inclusionProof?.checkpoint;
        if (note) { const c0 = noteFieldsMirror(note); cps.push({ origin: c0.origin, treeSize: c0.treeSize, rootHex: c0.rootHashHex, source: n }); }
      } catch { /* the witness pass reports unreadable receipts */ }
    }
  } catch { /* absent witness dir handled above */ }
  const seenCp = new Map();
  for (const cp of cps) {
    const k = `${cp.origin}#${cp.treeSize}`;
    const prev = seenCp.get(k);
    if (prev && prev.rootHex !== cp.rootHex) fails.push(`SPLIT VIEW at ${k}: root ${prev.rootHex.slice(0, 12)}… (${prev.source}) vs ${cp.rootHex.slice(0, 12)}… (${cp.source})`);
    if (!prev) seenCp.set(k, cp);
  }
  const censusStr = Object.entries(censusActual).map(([k, x]) => `${k} ${x}`).join(', ') || 'none';
  if (fails.length) {
    console.log(`\nGOSSIP FAIL — second observer (${obsNames.length} observation(s), census: ${censusStr})`);
    for (const x of fails) console.log(`      FAIL: ${x}`);
    return false;
  }
  console.log(`\nGOSSIP OK  second observer: ${obsNames.length} observation(s) fully re-verified offline (census: ${censusStr}); ${receiptNames.length} engine gossip receipt(s); split-view sweep clean across ${cps.length} checkpoint(s)  [REPORTED — same operator, second vantage point: stated in every receipt]`);
  return true;
}

// ---- generation 7: proof-of-recomputation --------------------------------
// Self-contained mirror of the deterministic replay math (src/formulas.mjs,
// src/strategy.mjs, src/portfolio.mjs, src/backtest.mjs) with byte-exact
// operation order, so recomputed IEEE-754 doubles are bit-identical to the
// engine's. Imports NOTHING from src/ — the verifier audits the engine, it
// does not trust it. Transcendentals (Math.log/exp/sqrt) are deterministic
// across platforms on V8's portable fdlibm port (Node ≥ 20); a mismatch
// therefore means tampered/false numbers, not float noise (METHODOLOGY.md).
//
// The signal-score arithmetic (squash/Hoeffding/Λ roll-up) is deliberately
// NOT mirrored here: backtest results contain no conviction values, and for
// in-range inputs that arithmetic cannot throw or alter the trade action —
// only periodReturn / zScore / annualizedVol gate the action path.

function meanStdM7(xs) {
  if (!Array.isArray(xs) || xs.length < 2) return null;
  const m = xs.reduce((a, b) => a + b, 0) / xs.length;
  const v = xs.reduce((a, b) => a + (b - m) * (b - m), 0) / xs.length;
  return { mean: m, std: Math.sqrt(v) };
}
function periodReturnM7(closes, lookback) {
  if (!Array.isArray(closes) || closes.length < lookback + 1) return null;
  const now = closes[closes.length - 1];
  const then = closes[closes.length - 1 - lookback];
  if (!(then > 0) || !Number.isFinite(now)) return null;
  return now / then - 1;
}
function zScoreM7(closes, window) {
  if (!Array.isArray(closes) || closes.length < window + 1) return null;
  const win = closes.slice(-window - 1, -1);
  const ms = meanStdM7(win);
  if (!ms || !(ms.std > 0)) return null;
  return (closes[closes.length - 1] - ms.mean) / ms.std;
}
function logReturnsM7(closes) {
  const out = [];
  for (let i = 1; i < closes.length; i++) {
    if (!(closes[i - 1] > 0) || !(closes[i] > 0)) return null;
    out.push(Math.log(closes[i] / closes[i - 1]));
  }
  return out;
}
function annualizedVolM7(closes, window) {
  const rets = logReturnsM7(closes.slice(-(window + 1)));
  if (!rets || rets.length < 2) return null;
  const ms = meanStdM7(rets);
  if (!ms) return null;
  return ms.std * Math.sqrt(365);
}
/** Action-determining core of src/strategy.mjs evaluate() (see note above). */
function evaluateActionM7(series, params) {
  const closes = series.map((s) => s.close);
  const { momentumLookback, zWindow, zEntry, volWindow } = params;
  const momRet = periodReturnM7(closes, momentumLookback);
  const z = zScoreM7(closes, zWindow);
  const vol = annualizedVolM7(closes, volWindow);
  if (momRet === null || z === null || vol === null) return 'ABSTAIN';
  let action = 'HOLD';
  if (momRet > 0 && z <= -zEntry) action = 'ENTER_LONG';
  else if (momRet > 0 && Math.abs(z) < zEntry) action = 'ENTER_LONG';
  else if (z >= 0 && momRet <= 0) action = 'EXIT_LONG';
  return action;
}
function makeBookM7({ startingCashUsd, costModel }) {
  if (!(startingCashUsd > 0)) throw new Error('startingCashUsd must be > 0');
  if (!costModel || !Number.isFinite(costModel.feeBps) || !Number.isFinite(costModel.slippageBps)) {
    throw new Error('explicit costModel {feeBps, slippageBps} required (MODELED)');
  }
  return { cashMicro: toMicroB(startingCashUsd), positions: {}, fills: [], costModel };
}
function paperFillM7(book, { asset, side, notionalUsd, qtyE9: sellQtyE9, price, atIso, reason }) {
  if (!(price > 0)) throw new Error('fill requires observed price > 0');
  const costRate = (book.costModel.feeBps + book.costModel.slippageBps) / 10_000;
  const pos = book.positions[asset] ?? { qtyE9: 0n, costMicro: 0n };
  let fill;
  if (side === 'BUY') {
    if (!(notionalUsd > 0)) throw new Error('BUY requires notionalUsd > 0');
    const notionalMicro = toMicroB(notionalUsd);
    if (book.cashMicro < notionalMicro) throw new Error('insufficient paper cash (no leverage in paper book)');
    const effPrice = price * (1 + costRate);
    const qtyE9 = (notionalMicro * QTY_B) / toMicroB(effPrice);
    book.cashMicro -= notionalMicro;
    pos.qtyE9 += qtyE9;
    pos.costMicro += notionalMicro;
    fill = { asset, side, qtyE9: qtyE9.toString(), atIso, reason };
  } else if (side === 'SELL') {
    const q = typeof sellQtyE9 === 'bigint' ? sellQtyE9 : BigInt(sellQtyE9 ?? 0);
    if (!(q > 0n)) throw new Error('SELL requires qtyE9 > 0');
    if (pos.qtyE9 < q) throw new Error('insufficient paper position (no shorting in v1 paper book)');
    const effPrice = price * (1 - costRate);
    const proceedsMicro = (q * toMicroB(effPrice)) / QTY_B;
    book.cashMicro += proceedsMicro;
    pos.qtyE9 -= q;
    if (pos.qtyE9 === 0n) pos.costMicro = 0n;
    fill = { asset, side, qtyE9: q.toString(), atIso, reason };
  } else {
    throw new Error(`unknown side ${side}`);
  }
  book.positions[asset] = pos;
  book.fills.push(fill);
  return fill;
}
function markToMarketM7(book, pricesByAsset, atIso) {
  let equityMicro = book.cashMicro;
  let unpriced = 0;
  for (const [asset, pos] of Object.entries(book.positions)) {
    if (pos.qtyE9 === 0n) continue;
    const p = pricesByAsset[asset];
    if (!(p > 0)) { unpriced++; continue; }
    const valueMicro = (pos.qtyE9 * toMicroB(p)) / QTY_B;
    equityMicro += valueMicro;
  }
  return {
    atIso,
    cashUsd: microStrB(book.cashMicro),
    equityUsd: unpriced === 0 ? microStrB(equityMicro) : null,
  };
}
function maxDrawdownM7(equity) {
  let peak = -Infinity, mdd = 0;
  for (const e of equity) {
    peak = Math.max(peak, e);
    if (peak > 0) mdd = Math.max(mdd, (peak - e) / peak);
  }
  return mdd;
}
/** Byte-exact mirror of src/backtest.mjs replaySeries(). */
function replaySeriesM7(series, params, costModel, startingCashUsd = 10_000) {
  const book = makeBookM7({ startingCashUsd, costModel });
  const equity = [];
  let inPosition = false;
  const trades = [];
  const warmup = Math.max(params.momentumLookback, params.zWindow, params.volWindow) + 2;
  for (let i = warmup; i < series.length - 1; i++) {
    const window = series.slice(0, i + 1);
    const action = evaluateActionM7(window, params);
    const nextBar = series[i + 1];
    const atIso = new Date(nextBar.tMs).toISOString();
    if (action === 'ENTER_LONG' && !inPosition) {
      const cashUsd = Number(markToMarketM7(book, {}, atIso).cashUsd);
      const notional = Math.floor(cashUsd * params.positionFraction * 100) / 100;
      if (notional >= 10) {
        paperFillM7(book, { asset: 'ASSET', side: 'BUY', notionalUsd: notional, price: nextBar.close, atIso, reason: 'ENTER_LONG @ next close (no lookahead)' });
        inPosition = true;
        trades.push({ t: atIso, side: 'BUY', price: nextBar.close });
      }
    } else if (action === 'EXIT_LONG' && inPosition) {
      const pos = book.positions.ASSET;
      if (pos.qtyE9 > 0n) {
        paperFillM7(book, { asset: 'ASSET', side: 'SELL', qtyE9: pos.qtyE9, price: nextBar.close, atIso, reason: 'EXIT_LONG @ next close (no lookahead)' });
        inPosition = false;
        trades.push({ t: atIso, side: 'SELL', price: nextBar.close });
      }
    }
    const mtm = markToMarketM7(book, { ASSET: series[i + 1].close }, atIso);
    if (mtm.equityUsd !== null) equity.push(Number(mtm.equityUsd));
  }
  const last = series[series.length - 1];
  const finalMark = markToMarketM7(book, { ASSET: last.close }, new Date(last.tMs).toISOString());
  const finalEquity = finalMark.equityUsd !== null ? Number(finalMark.equityUsd) : null;
  let wins = 0, roundTrips = 0;
  for (let i = 0; i + 1 < trades.length; i += 2) {
    if (trades[i].side === 'BUY' && trades[i + 1].side === 'SELL') {
      roundTrips++;
      if (trades[i + 1].price > trades[i].price) wins++;
    }
  }
  return {
    finalEquityUsd: finalEquity,
    totalReturn: finalEquity === null ? null : finalEquity / startingCashUsd - 1,
    maxDrawdown: equity.length ? maxDrawdownM7(equity) : null,
    nTrades: trades.length,
    nRoundTrips: roundTrips,
    winRate: roundTrips > 0 ? wins / roundTrips : null,
    winRateNote: roundTrips < 10 ? `only ${roundTrips} round trips — win rate is statistically weak evidence` : undefined,
    openAtEnd: inPosition,
  };
}
/** Byte-exact mirror of src/backtest.mjs walkForward(). */
function walkForwardM7(series, grid, costModel, isFraction, startingCashUsd) {
  const splitIdx = Math.floor(series.length * isFraction);
  const inSample = series.slice(0, splitIdx);
  const outSample = series.slice(splitIdx - 60 >= 0 ? splitIdx - 60 : 0); // carry warmup context
  const results = [];
  for (const params of grid) {
    results.push({
      params,
      inSample: replaySeriesM7(inSample, params, costModel, startingCashUsd),
      outOfSample: replaySeriesM7(outSample, params, costModel, startingCashUsd),
    });
  }
  return {
    splitIndex: splitIdx,
    inSampleBars: inSample.length,
    outOfSampleBars: series.length - splitIdx,
    populationSize: grid.length,
    cherryPickNote: 'ALL configs reported (full population). Selecting the best cell after the fact is multiple testing — see METHODOLOGY.md.',
    results,
  };
}
/** First-divergence finder for honest mismatch messages. */
function diffPathM7(a, b, path = '$') {
  if (a === b) return null;
  const ta = a === null ? 'null' : typeof a;
  const tb = b === null ? 'null' : typeof b;
  if (ta !== tb) return `${path} (recomputed ${ta} ${JSON.stringify(a) ?? String(a)} vs signed ${tb} ${JSON.stringify(b) ?? String(b)})`;
  if (Array.isArray(a) && Array.isArray(b)) {
    if (a.length !== b.length) return `${path}.length (recomputed ${a.length} vs signed ${b.length})`;
    for (let i = 0; i < a.length; i++) { const d = diffPathM7(a[i], b[i], `${path}[${i}]`); if (d) return d; }
    return null;
  }
  if (ta === 'object') {
    const keys = new Set([...Object.keys(a).filter((k) => a[k] !== undefined), ...Object.keys(b).filter((k) => b[k] !== undefined)]);
    for (const k of [...keys].sort()) { const d = diffPathM7(a?.[k], b?.[k], `${path}.${k}`); if (d) return d; }
    return null;
  }
  return `${path} (recomputed ${JSON.stringify(a)} vs signed ${JSON.stringify(b)})`;
}
const BACKTEST_PREDICATE_M7 = 'https://szl.holdings/quant/backtest/v1';
/**
 * Recompute one backtest receipt's numbers from its archived dataset.
 * Returns null for non-backtest receipts; { ok, skip? } | { ok:false, fails }.
 */
function recomputeBacktest(file, datasetsRoot) {
  let st;
  try {
    const env = JSON.parse(readFileSync(file, 'utf8'));
    st = JSON.parse(Buffer.from(env.payload, 'base64').toString('utf8'));
  } catch { return null; } // unreadable — the signature pass already failed it
  if (st?.predicateType !== BACKTEST_PREDICATE_M7) return null;
  const summary = st.predicate?.summary;
  if (!summary) return { ok: false, fails: ['backtest receipt missing predicate.summary'] };
  if (!summary.datasetArchive) {
    return { ok: true, skip: 'pre-generation-7 receipt (no datasetArchive) — numbers cannot be recomputed; signature/doctrine checks only' };
  }
  const fails = [];
  const pinned = String(summary.dataset?.sha256 ?? '');
  if (!/^[0-9a-f]{64}$/.test(pinned)) return { ok: false, fails: ['dataset.sha256 is not 64 lowercase hex chars'] };
  const expectPath = `data/datasets/${pinned}.json`;
  if (summary.datasetArchive.path !== expectPath) {
    return { ok: false, fails: [`datasetArchive.path "${summary.datasetArchive.path}" is not the canonical "${expectPath}" (anchored exact match required — no traversal, no aliases)`] };
  }
  let bytes;
  try { bytes = readFileSync(join(datasetsRoot, expectPath)); } catch {
    return { ok: false, fails: [`declared dataset archive MISSING at ${expectPath} — a MEASURED claim whose inputs are gone does not re-verify (fail closed)`] };
  }
  if (sha256Hex(bytes) !== pinned) {
    return { ok: false, fails: [`archived dataset bytes hash ${sha256Hex(bytes).slice(0, 16)}… ≠ pinned ${pinned.slice(0, 16)}… — dataset bytes TAMPERED or corrupted`] };
  }
  let series;
  try { series = JSON.parse(bytes.toString('utf8')); } catch { return { ok: false, fails: ['archived dataset is not valid JSON'] }; }
  if (!Array.isArray(series) || series.length < 2 || !series.every((r) => r && Number.isFinite(r.tMs) && Number.isFinite(r.close) && r.close > 0)) {
    return { ok: false, fails: ['archived dataset rows invalid — need [{tMs, close>0}, …]'] };
  }
  if (summary.dataset?.n !== series.length) fails.push(`dataset.n ${summary.dataset?.n} ≠ archived row count ${series.length}`);
  const method = summary.method ?? {};
  const replay = method.replay ?? {};
  const cm = method.costModel ?? {};
  if (!Array.isArray(method.grid) || method.grid.length === 0) fails.push('method.grid missing/empty — cannot recompute');
  if (!Number.isFinite(replay.isFraction) || !(replay.isFraction > 0 && replay.isFraction < 1)) fails.push('method.replay.isFraction missing/invalid — replay contract incomplete');
  if (!Number.isFinite(replay.startingCashUsd) || !(replay.startingCashUsd > 0)) fails.push('method.replay.startingCashUsd missing/invalid — replay contract incomplete');
  if (!Number.isFinite(cm.feeBps) || !Number.isFinite(cm.slippageBps)) fails.push('method.costModel missing finite feeBps/slippageBps');
  if (fails.length) return { ok: false, fails };
  let recomputed;
  try { recomputed = walkForwardM7(series, method.grid, { feeBps: cm.feeBps, slippageBps: cm.slippageBps }, replay.isFraction, replay.startingCashUsd); }
  catch (e) { return { ok: false, fails: [`replay threw: ${e.message}`] }; }
  if (canonicalize(recomputed) !== canonicalize(summary.walkForward ?? null)) {
    const where = diffPathM7(recomputed, summary.walkForward ?? null);
    return { ok: false, fails: [`RECOMPUTE MISMATCH at ${where} — the signed numbers do NOT re-derive from the archived dataset (a valid signature cannot rescue false numbers)`] };
  }
  return { ok: true, recomputed: true, cells: method.grid.length, bars: series.length };
}

const args = process.argv.slice(2);
let pinnedKey = null;
let chainDir = null;
let bookDir = null;
let refusalsDir = null;
let witnessRoot = null;
let rekorPubPath = 'keys/rekor_pubkey.pem';
let tsaAnchorsDir = 'keys/tsa';
let observerPubPath = 'keys/observer_pubkey.json';
let datasetsRoot = join(dirname(fileURLToPath(import.meta.url)), '..'); // repo root — datasetArchive paths are repo-relative
const files = [];
for (let i = 0; i < args.length; i++) {
  if (args[i] === '--pubkey') {
    const pj = JSON.parse(readFileSync(args[++i], 'utf8'));
    pinnedKey = createPublicKey({ key: Buffer.from(pj.publicKeySpkiBase64, 'base64'), type: 'spki', format: 'der' });
  } else if (args[i] === '--dir') {
    const dir = args[++i];
    for (const f of readdirSync(dir)) {
      if (f.endsWith('.json') && statSync(join(dir, f)).isFile()) files.push(join(dir, f));
    }
  } else if (args[i] === '--chain') {
    chainDir = args[++i];
  } else if (args[i] === '--book') {
    bookDir = args[++i];
  } else if (args[i] === '--refusals') {
    refusalsDir = args[++i];
  } else if (args[i] === '--witness') {
    witnessRoot = args[++i];
  } else if (args[i] === '--rekor-pubkey') {
    rekorPubPath = args[++i];
  } else if (args[i] === '--tsa-anchors') {
    tsaAnchorsDir = args[++i];
  } else if (args[i] === '--observer-pubkey') {
    observerPubPath = args[++i];
  } else if (args[i] === '--datasets-root') {
    datasetsRoot = args[++i];
  } else files.push(args[i]);
}
if (files.length === 0 && !chainDir && !bookDir && !refusalsDir && !witnessRoot) {
  console.error('usage: node verify/verify.mjs [--pubkey keys/engine_pubkey.json] [--rekor-pubkey keys/rekor_pubkey.pem] [--tsa-anchors keys/tsa] [--observer-pubkey keys/observer_pubkey.json] [--datasets-root DIR] (--dir receipts/ | --chain ledger/ | --book ledger/ | --refusals ledger/ | --witness rootdir/ | receipt.json ...)');
  process.exit(2);
}
let allOk = true;
const recompStats = { recomputed: 0, skipped: 0, failed: 0 };
for (const f of files.sort()) {
  const r = verifyFile(f, pinnedKey);
  allOk &&= r.ok;
  console.log(`${r.ok ? 'PASS' : 'FAIL'}  ${f}${r.keyid ? `  keyid=${r.keyid}` : ''}`);
  for (const n of r.notes ?? []) console.log(`      note: ${n}`);
  for (const x of r.fails ?? []) console.log(`      FAIL: ${x}`);
  if (r.ok) {
    // generation 7: MEASURED backtest numbers must re-derive from archived bytes
    const rr = recomputeBacktest(f, datasetsRoot);
    if (rr) {
      if (rr.ok && rr.recomputed) {
        recompStats.recomputed++;
        console.log(`      recompute: OK — ${rr.cells} grid cell(s) re-derived bit-exact from ${rr.bars} archived bars (MEASURED, recomputed)`);
      } else if (rr.ok && rr.skip) {
        recompStats.skipped++;
        console.log(`      recompute: SKIP — ${rr.skip}`);
      } else {
        recompStats.failed++;
        allOk = false;
        for (const x of rr.fails) console.log(`      RECOMPUTE FAIL: ${x}`);
      }
    }
  }
}
if (files.length > 0) console.log(allOk ? `\nAll ${files.length} receipt(s) verified.` : '\nVERIFICATION FAILED');
if (recompStats.recomputed + recompStats.skipped + recompStats.failed > 0) {
  console.log(`Recompute (generation 7): ${recompStats.recomputed} backtest receipt(s) re-derived bit-exact, ${recompStats.skipped} skipped (pre-gen7), ${recompStats.failed} FAILED.`);
}
if (chainDir) allOk = verifyChain(chainDir, pinnedKey) && allOk;
if (bookDir) allOk = verifyBook(bookDir, pinnedKey) && allOk;
if (refusalsDir) allOk = verifyRefusals(refusalsDir, pinnedKey) && allOk;
if (witnessRoot) allOk = verifyWitness(witnessRoot, pinnedKey, rekorPubPath) && allOk;
if (witnessRoot) allOk = verifyTsa(witnessRoot, pinnedKey, tsaAnchorsDir) && allOk;
if (witnessRoot) allOk = verifyGossip(witnessRoot, pinnedKey, rekorPubPath, observerPubPath) && allOk;
process.exit(allOk ? 0 : 1);
