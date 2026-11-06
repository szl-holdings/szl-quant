/** Gossip archive bounds — the real `quant.mjs witness` path, end to end and offline.
 *
 * Each case runs a sandbox COPY of the engine (bin/quant.mjs derives ROOT from its
 * own path and ensureIdentity rewrites ROOT/keys/engine_pubkey.json, so the repo's
 * pins are never touched) with global fetch replaced by fixtures/gossip/fetch-stub.mjs.
 * The ledger is the REAL seq-13 chain link and witness receipt that the REAL
 * observation fixture binds to:
 *   chain_0013.receipt.json = `git show origin/ledger:ledger/20260716T202015Z_run16/chain_0013.receipt.json`
 *     (sha256 90e20305…, the observation's ledger.chainSha256)
 *   obs_real.observation.json = ledger branch witness/gossip/obs_0013_1784234137588.observation.json (byte-identical)
 * A throwaway key signs the gossip receipt; the real engine key is never needed.
 *
 * Pins the gossip doctrine stated on gossipPass: an unreachable observation is a
 * counted gap; a BAD observation (here, one over the MAX_OBS_BYTES cap) is a loud
 * rejection recorded in the signed receipt, never a silent drop. The cap also bounds
 * how much of a body is read at all. */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { generateKeyPairSync } from 'node:crypto';

const REPO = join(dirname(fileURLToPath(import.meta.url)), '..');
const FIX = join(REPO, 'test', 'fixtures', 'gossip');
const STUB = pathToFileURL(join(FIX, 'fetch-stub.mjs')).href;
const CAP = 1 << 20; // MAX_OBS_BYTES in bin/quant.mjs
const CHUNK = 64 * 1024; // fetch-stub stream chunk size
const RUN_DIR = '20260716T202015Z_run16';
const WITNESS_FILE = 'witness_0013_1784233307672.receipt.json';
const OBS_FILE = join(FIX, 'obs_real.observation.json');
const OBS_NAME = 'obs_0013_1784234137588.observation.json';
const OBS_BYTES = readFileSync(OBS_FILE);
const OBS_URL = `https://raw.githubusercontent.com/szl-holdings/szl-quant-witness/observations/observations/${OBS_NAME}`;
const LISTING = [{ name: OBS_NAME, path: `observations/${OBS_NAME}`, type: 'file', size: OBS_BYTES.length, download_url: OBS_URL }];

function runWitness(route) {
  const root = mkdtempSync(join(tmpdir(), 'szl-quant-gossip-'));
  try {
    for (const d of ['bin', 'src', 'keys']) cpSync(join(REPO, d), join(root, d), { recursive: true });
    const ledgerDir = join(root, 'work', 'ledger');
    const witnessDir = join(root, 'work', 'witness');
    mkdirSync(join(ledgerDir, RUN_DIR), { recursive: true });
    mkdirSync(witnessDir, { recursive: true });
    cpSync(join(FIX, 'chain_0013.receipt.json'), join(ledgerDir, RUN_DIR, 'chain_0013.receipt.json'));
    cpSync(join(FIX, WITNESS_FILE), join(witnessDir, WITNESS_FILE));
    const key = join(root, 'engine_key.pem');
    writeFileSync(key, generateKeyPairSync('ed25519').privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600 });
    const stub = join(root, 'stub.json');
    const pulledFile = join(root, 'pulled.txt');
    writeFileSync(stub, JSON.stringify({ listing: LISTING, bodies: { [OBS_URL]: route }, pulledFile }));
    const r = spawnSync(process.execPath, ['--import', STUB, join(root, 'bin', 'quant.mjs'), 'witness', '--ledger', ledgerDir, '--witness-dir', witnessDir], {
      cwd: join(root, 'work'),
      encoding: 'utf8',
      timeout: 60_000,
      env: { PATH: process.env.PATH, SZL_QUANT_KEY: key, GOSSIP_STUB: stub },
    });
    const gossipDir = join(witnessDir, 'gossip');
    const archived = existsSync(gossipDir) ? readdirSync(gossipDir).sort() : [];
    const receipts = readdirSync(witnessDir).filter((n) => /^gossip_\d{4}_\d+\.receipt\.json$/.test(n));
    const summary = receipts.length === 1
      ? JSON.parse(Buffer.from(JSON.parse(readFileSync(join(witnessDir, receipts[0]), 'utf8')).payload, 'base64').toString('utf8')).predicate.summary
      : null;
    return {
      r,
      archived,
      archivedBytes: archived.length ? readFileSync(join(gossipDir, archived[0])) : null,
      receipts,
      summary,
      pulled: existsSync(pulledFile) ? Number(readFileSync(pulledFile, 'utf8')) : null,
    };
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

test('gossip archive: a real observation is archived byte-exact under its listed name and accounted', () => {
  const { r, archived, archivedBytes, receipts, summary } = runWitness({ file: OBS_FILE });
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stdout, /gossip archived obs_0013_1784234137588\.observation\.json — verdict PREFIX_OK/);
  assert.deepEqual(archived, [OBS_NAME]);
  assert.ok(archivedBytes.equals(OBS_BYTES), 'archived bytes must be exactly the fetched bytes');
  assert.equal(receipts.length, 1);
  assert.deepEqual(summary.observations, { remoteTotal: 1, newArchived: 1, archivedTotal: 1, rejected: [], verdictCensus: { PREFIX_OK: 1 } });
});

test('gossip archive: an unreachable observation stays a counted gap, not a rejection', () => {
  const { r, archived, summary } = runWitness({ status: 503 });
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stdout, /gossip gap — could not fetch obs_0013_1784234137588\.observation\.json \(HTTP 503\)/);
  assert.deepEqual(archived, []);
  assert.equal(summary.observations.remoteTotal, 1);
  assert.equal(summary.observations.archivedTotal, 0);
  assert.deepEqual(summary.observations.rejected, []);
});

test('gossip archive: a validly signed observation over the cap is a loud signed rejection, not a silent gap', () => {
  // padded past the cap with JSON whitespace: still parseable and still verifiable, so only the size bound can refuse it
  const { r, archived, summary } = runWitness({ file: OBS_FILE, padTo: CAP + 1 });
  assert.equal(r.status, 0, r.stderr);
  assert.deepEqual(archived, [], 'an over-cap observation must not be archived');
  assert.doesNotMatch(r.stdout, /gossip gap — could not fetch/, 'the body was fetched; a size refusal is not a fetch gap');
  assert.match(r.stdout, /gossip REJECTED obs_0013_1784234137588\.observation\.json: observation exceeds the 1048576-byte cap/);
  assert.equal(summary.observations.rejected.length, 1);
  assert.equal(summary.observations.rejected[0].file, OBS_NAME);
  assert.match(summary.observations.rejected[0].reason, /exceeds the 1048576-byte cap/);
});

test('gossip archive: the cap bounds what is read — an oversized body is cancelled, never buffered whole', () => {
  const { r, archived, summary, pulled } = runWitness({ streamBytes: 16 * CAP });
  assert.equal(r.status, 0, r.stderr);
  assert.ok(pulled > CAP && pulled <= CAP + 4 * CHUNK, `engine pulled ${pulled} bytes of a ${16 * CAP}-byte body; the cap is ${CAP}`);
  assert.deepEqual(archived, []);
  assert.equal(summary.observations.rejected.length, 1);
  assert.match(summary.observations.rejected[0].reason, /exceeds the 1048576-byte cap/);
});
