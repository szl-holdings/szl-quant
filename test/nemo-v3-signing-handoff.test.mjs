import assert from 'node:assert/strict';
import {
  createHash,
  generateKeyPairSync,
  sign as signBytes,
} from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import {
  AUTH_SCHEMA,
  READY_STATE,
  canonicalize,
  pae,
  sha256,
  validateAuthorization,
  validateExactSpec,
  verifyExactEnvelope,
  verifyPinnedBridgeTree,
} from '../tools/nemo-v3-exact-signing-handoff.mjs';

const ROOT = resolve(fileURLToPath(new URL('..', import.meta.url)));
const ATTEMPT_1_AUTH_PATH = join(ROOT, 'authorizations', 'nemo-v3-20260722-exact.json');
const ATTEMPT_2_AUTH_PATH = join(
  ROOT,
  'authorizations',
  'nemo-v3-20260729-attempt-2-exact.json',
);

function loadAuthorization(path = ATTEMPT_2_AUTH_PATH) {
  return JSON.parse(readFileSync(path, 'utf8'));
}

function idsDigest(ids) {
  return createHash('sha256').update(`${ids.join('\n')}\n`).digest('hex');
}

test('predecessor authorization remains one exact artifact-only attempt', () => {
  const authorization = validateAuthorization(loadAuthorization(ATTEMPT_1_AUTH_PATH));
  assert.equal(authorization.schema, AUTH_SCHEMA);
  assert.equal(authorization.jobId, 'job-2026-nemo-v3-governed-attempt-1');
  assert.equal(authorization.bridge.revision, 'a14c417d8bcb52ff7b4cba43d656c6858fc93c4c');
  assert.equal(authorization.payload.canonicalSha256, '8a5c2e3f99711be84e45371824ca737d480e587ff61c55cc3d30ad96d2c62055');
  assert.equal(authorization.engine.keyId, '5c6cf59741ade920');
  assert.deepEqual(authorization.effects, {
    signExactReviewedPayload: true,
    artifactOnly: true,
    crossRepositoryWrite: false,
    training: false,
    candidateUpload: false,
    publication: false,
    deployment: false,
    promotion: false,
  });
});

test('successor authorization pins exact b21 owner-dispatch attempt', () => {
  const authorization = validateAuthorization(loadAuthorization());
  assert.equal(authorization.schema, AUTH_SCHEMA);
  assert.equal(authorization.jobId, 'job-2026-nemo-v3-governed-attempt-2');
  assert.equal(authorization.bridge.revision, '6d59b0efe448505c6206306874a255f7d426eb2c');
  assert.equal(
    authorization.payload.canonicalSha256,
    '84a808615ba1693935eee8cc9fa1a4c5a83d119b79ad7e9437380ec73756b90d',
  );
  assert.equal(
    authorization.payload.sourceRevision,
    'b21b8fb65400e7eb39595365c5f54c80ed78aa67',
  );
  assert.deepEqual(authorization.payload.ownerDispatch, {
    workflowIdentity: 'szl-holdings/a11oy/.github/workflows/nemo-v3-isolated-owner-dispatch.yml@refs/heads/main',
    workflowBlob: '7e08ffc8aa87b78d0fa1618d7d3c3e68cb81ca33',
    workflowVersion: 'nemo-v3-owner-dispatch.v2',
    trainingImage: 'unsloth/unsloth@sha256:9cc97606fc386b4b13455285eb7bd2668f51530988a9c2578707fe6cdfc46123',
    candidateUpload: false,
    modelCardUpload: false,
    datasetUpload: false,
    receiptsRepoId: 'SZLHOLDINGS/szl-training-receipts',
  });
});

test('authorization refuses any effect expansion', () => {
  const authorization = loadAuthorization();
  authorization.effects.crossRepositoryWrite = true;
  assert.throws(() => validateAuthorization(authorization), /crossRepositoryWrite/);
});

test('authorization refuses cross-attempt identity substitution', () => {
  const authorization = loadAuthorization();
  authorization.jobId = 'job-2026-nemo-v3-governed-attempt-1';
  assert.throws(() => validateAuthorization(authorization), /authorization.jobId/);

  const sourceTampered = loadAuthorization();
  sourceTampered.payload.sourceRevision = 'a5351c8e37a7cfe54e0c3cf53c8bbd460a16c11c';
  assert.throws(() => validateAuthorization(sourceTampered), /payload.sourceRevision/);

  const dispatchExpanded = loadAuthorization();
  dispatchExpanded.payload.ownerDispatch.candidateUpload = true;
  assert.throws(() => validateAuthorization(dispatchExpanded), /candidateUpload/);
});

test('exact bridge revision, signer, spec, and engine pin match the reviewed tree', {
  skip: !process.env.BRIDGE_ROOT,
}, () => {
  const authorization = validateAuthorization(loadAuthorization());
  verifyPinnedBridgeTree(resolve(process.env.BRIDGE_ROOT), authorization);
  const spec = JSON.parse(
    readFileSync(join(resolve(process.env.BRIDGE_ROOT), authorization.bridge.specPath), 'utf8'),
  );
  validateExactSpec(spec, authorization);
  assert.equal(sha256(Buffer.from(canonicalize(spec), 'utf8')), authorization.payload.canonicalSha256);
});

test('DSSE verifier accepts one exact signature and refuses payload tampering', () => {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const spki = publicKey.export({ type: 'spki', format: 'der' });
  const keyId = sha256(spki).slice(0, 16);
  const spec = {
    jobId: 'fixture',
    values: [1, true, 'x'],
    nested: { z: 2, a: null },
  };
  const payloadBytes = Buffer.from(canonicalize(spec), 'utf8');
  const payloadType = 'application/vnd.szl.test+json';
  const signature = signBytes(null, pae(payloadType, payloadBytes), privateKey);
  const authorization = {
    payload: { type: payloadType, canonicalSha256: sha256(payloadBytes) },
    engine: {
      keyId,
      publicKeySpkiBase64: spki.toString('base64'),
    },
  };
  const envelope = {
    payloadType,
    payload: payloadBytes.toString('base64'),
    signatures: [{ keyid: keyId, sig: signature.toString('base64') }],
    publicKeySpkiBase64: spki.toString('base64'),
  };
  const verified = verifyExactEnvelope(envelope, spec, authorization);
  assert.equal(verified.payloadSha256, sha256(payloadBytes));
  assert.equal(verified.engineKeyId, keyId);

  const tampered = structuredClone(envelope);
  tampered.payload = Buffer.from(canonicalize({ ...spec, extra: true }), 'utf8').toString('base64');
  assert.throws(
    () => verifyExactEnvelope(tampered, spec, authorization),
    /payload bytes differ/,
  );
});

test('DSSE verifier refuses extra signatures and key substitution', () => {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const spki = publicKey.export({ type: 'spki', format: 'der' });
  const keyId = sha256(spki).slice(0, 16);
  const spec = { a: 1 };
  const payloadBytes = Buffer.from(canonicalize(spec), 'utf8');
  const payloadType = 'application/vnd.szl.test+json';
  const signature = signBytes(null, pae(payloadType, payloadBytes), privateKey).toString('base64');
  const authorization = {
    payload: { type: payloadType, canonicalSha256: sha256(payloadBytes) },
    engine: { keyId, publicKeySpkiBase64: spki.toString('base64') },
  };
  const envelope = {
    payloadType,
    payload: payloadBytes.toString('base64'),
    signatures: [{ keyid: keyId, sig: signature }, { keyid: keyId, sig: signature }],
    publicKeySpkiBase64: spki.toString('base64'),
  };
  assert.throws(() => verifyExactEnvelope(envelope, spec, authorization), /exactly one signature/);

  envelope.signatures = [{ keyid: '0'.repeat(16), sig: signature }];
  assert.throws(() => verifyExactEnvelope(envelope, spec, authorization), /signature keyId/);
});

test('workflow is PR-credentialless and protected-main artifact-only', () => {
  const workflow = readFileSync(
    join(ROOT, '.github', 'workflows', 'nemo-v3-exact-signing-handoff.yml'),
    'utf8',
  );
  assert.match(workflow, /pull_request:/);
  assert.match(workflow, /push:/);
  assert.match(workflow, /github\.event_name == 'push'/);
  assert.match(workflow, /secrets\.SZL_QUANT_SIGNING_KEY_PEM/);
  assert.match(workflow, /actions\/upload-artifact@/);
  assert.match(workflow, /persist-credentials: false/);
  assert.doesNotMatch(workflow, /git push/);
  assert.doesNotMatch(workflow, /contents:\s*write/);
  assert.doesNotMatch(workflow, /workflow_dispatch/);
  assert.match(workflow, /nemo-v3-20260729-attempt-2-exact\.json/);
  assert.match(workflow, /job-2026-nemo-v3-governed-attempt-2\.json/);
  assert.match(workflow, new RegExp(READY_STATE));
});

test('test fixture digest helper remains deterministic', () => {
  assert.equal(idsDigest(['a', 'b']), sha256(Buffer.from('a\nb\n')));
});
