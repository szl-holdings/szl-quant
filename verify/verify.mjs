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
import { createPublicKey, createHash, verify as edVerify } from 'node:crypto';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';

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

// ---- main ----
const args = process.argv.slice(2);
let pinnedKey = null;
let chainDir = null;
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
  } else files.push(args[i]);
}
if (files.length === 0 && !chainDir) {
  console.error('usage: node verify/verify.mjs [--pubkey keys/engine_pubkey.json] (--dir receipts/ | --chain ledger/ | receipt.json ...)');
  process.exit(2);
}
let allOk = true;
for (const f of files.sort()) {
  const r = verifyFile(f, pinnedKey);
  allOk &&= r.ok;
  console.log(`${r.ok ? 'PASS' : 'FAIL'}  ${f}${r.keyid ? `  keyid=${r.keyid}` : ''}`);
  for (const n of r.notes ?? []) console.log(`      note: ${n}`);
  for (const x of r.fails ?? []) console.log(`      FAIL: ${x}`);
}
if (files.length > 0) console.log(allOk ? `\nAll ${files.length} receipt(s) verified.` : '\nVERIFICATION FAILED');
if (chainDir) allOk = verifyChain(chainDir, pinnedKey) && allOk;
process.exit(allOk ? 0 : 1);
