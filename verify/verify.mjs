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

// ---- main ----
const args = process.argv.slice(2);
let pinnedKey = null;
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
  } else files.push(args[i]);
}
if (files.length === 0) {
  console.error('usage: node verify/verify.mjs [--pubkey keys/engine_pubkey.json] (--dir receipts/ | receipt.json ...)');
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
console.log(allOk ? `\nAll ${files.length} receipt(s) verified.` : '\nVERIFICATION FAILED');
process.exit(allOk ? 0 : 1);
