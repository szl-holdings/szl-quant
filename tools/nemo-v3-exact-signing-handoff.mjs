#!/usr/bin/env node
/**
 * Verify the exact reviewed SZL-Nemo v3 DSSE envelope and emit an artifact-only
 * handoff receipt. This module never reads a private key and never writes another
 * repository. Signing remains delegated to the already reviewed bridge signer.
 */

import {
  createHash,
  createPublicKey,
  verify as verifySignature,
} from 'node:crypto';
import { execFileSync } from 'node:child_process';
import {
  copyFileSync,
  mkdirSync,
  readFileSync,
  writeFileSync,
} from 'node:fs';
import { basename, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

export const AUTH_SCHEMA = 'szl.nemo-v3-signing-authorization/v1';
export const RECEIPT_SCHEMA = 'szl.nemo-v3-signing-handoff/v1';
export const READY_STATE = 'ENGINE_SIGNED_QUEUE_ARTIFACT_READY_FOR_PROTECTED_IMPORT';
export const ADMITTED_AUTHORIZATIONS = Object.freeze({
  'nemo-v3-20260722-exact-single-attempt': Object.freeze({
    jobId: 'job-2026-nemo-v3-governed-attempt-1',
    expiresAt: '2026-08-05T16:30:00Z',
    bridgeRevision: 'a14c417d8bcb52ff7b4cba43d656c6858fc93c4c',
    signerGitBlob: '5f6b1f5edd290316347e3dcc5afcef07f3a37b46',
    specPath: 'jobspecs/nemo-v3-20260722-reviewed.json',
    specGitBlob: 'ff8c3b76fff8ecffa7165bab3bbd4b7657c2a8d8',
    queuePath: 'queue/pending/job-2026-nemo-v3-governed-attempt-1.json',
    canonicalSha256: '8a5c2e3f99711be84e45371824ca737d480e587ff61c55cc3d30ad96d2c62055',
    sourceRevision: 'a5351c8e37a7cfe54e0c3cf53c8bbd460a16c11c',
    ownerDispatch: undefined,
  }),
  'nemo-v3-20260729-attempt-2-b21-exact-single-attempt': Object.freeze({
    jobId: 'job-2026-nemo-v3-governed-attempt-2',
    expiresAt: '2026-08-12T23:08:49Z',
    bridgeRevision: '6d59b0efe448505c6206306874a255f7d426eb2c',
    signerGitBlob: '997e9c0e5d6f4ab273ceff88d33b4bc0cfdad700',
    specPath: 'jobspecs/nemo-v3-20260729-attempt-2-reviewed.json',
    specGitBlob: '7c15bce93f23061306cbbc7d166adf9e06287ae6',
    queuePath: 'queue/pending/job-2026-nemo-v3-governed-attempt-2.json',
    canonicalSha256: '84a808615ba1693935eee8cc9fa1a4c5a83d119b79ad7e9437380ec73756b90d',
    sourceRevision: 'b21b8fb65400e7eb39595365c5f54c80ed78aa67',
    ownerDispatch: Object.freeze({
      workflowIdentity: 'szl-holdings/a11oy/.github/workflows/nemo-v3-isolated-owner-dispatch.yml@refs/heads/main',
      workflowBlob: '7e08ffc8aa87b78d0fa1618d7d3c3e68cb81ca33',
      workflowVersion: 'nemo-v3-owner-dispatch.v2',
      trainingImage: 'unsloth/unsloth@sha256:9cc97606fc386b4b13455285eb7bd2668f51530988a9c2578707fe6cdfc46123',
      candidateUpload: false,
      modelCardUpload: false,
      datasetUpload: false,
      receiptsRepoId: 'SZLHOLDINGS/szl-training-receipts',
    }),
  }),
});

const BRIDGE_REPOSITORY = 'szl-holdings/szl-gpu-bridge';
const ENGINE_KEY_ID = '5c6cf59741ade920';
const ENGINE_PUBLIC_KEY_SPKI = 'MCowBQYDK2VwAyEArBOmZZSDK+n7Qq1HJYbqNuX9YymnsRWbzSGHHnhsERM=';
const ENGINE_PUBLIC_KEY_GIT_BLOB = '44515ae6b96312f2a1d51806c1e2ef1d43d6237f';
const PAYLOAD_TYPE = 'application/vnd.szl.gpu-bridge.nemo-v3.jobspec.v1+json';

export function canonicalize(value) {
  if (value === null || typeof value === 'number' || typeof value === 'boolean') {
    return JSON.stringify(value);
  }
  if (typeof value === 'string') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(',')}]`;
  if (typeof value === 'object') {
    const keys = Object.keys(value).sort();
    return `{${keys.map((key) => `${JSON.stringify(key)}:${canonicalize(value[key])}`).join(',')}}`;
  }
  throw new Error(`non-serializable value of type ${typeof value}`);
}

export function pae(payloadType, payloadBytes) {
  const typeBytes = Buffer.from(payloadType, 'utf8');
  return Buffer.concat([
    Buffer.from('DSSEv1 ', 'utf8'),
    Buffer.from(String(typeBytes.length), 'utf8'),
    Buffer.from(' ', 'utf8'),
    typeBytes,
    Buffer.from(' ', 'utf8'),
    Buffer.from(String(payloadBytes.length), 'utf8'),
    Buffer.from(' ', 'utf8'),
    payloadBytes,
  ]);
}

export function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

function object(value, name) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${name} must be an object`);
  }
  return value;
}

function equal(actual, expected, label) {
  if (actual !== expected) {
    throw new Error(`${label} mismatch: expected ${JSON.stringify(expected)}, observed ${JSON.stringify(actual)}`);
  }
}

function exactKeys(value, expected, label) {
  const observed = Object.keys(object(value, label)).sort();
  const admitted = [...expected].sort();
  if (JSON.stringify(observed) !== JSON.stringify(admitted)) {
    throw new Error(`${label} fields must be exact`);
  }
}

function decodeBase64(value, label) {
  if (typeof value !== 'string' || value.length === 0 || !/^[A-Za-z0-9+/]+={0,2}$/.test(value)) {
    throw new Error(`${label} must be canonical non-empty base64`);
  }
  const decoded = Buffer.from(value, 'base64');
  if (decoded.toString('base64') !== value) {
    throw new Error(`${label} is not canonical base64`);
  }
  return decoded;
}

function git(root, ...args) {
  return execFileSync('git', ['-C', root, ...args], {
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
  }).trim();
}

export function validateAuthorization(authorization) {
  object(authorization, 'authorization');
  exactKeys(
    authorization,
    ['schema', 'authorizationId', 'jobId', 'expiresAt', 'bridge', 'payload', 'engine', 'effects'],
    'authorization',
  );
  equal(authorization.schema, AUTH_SCHEMA, 'authorization.schema');
  const admitted = ADMITTED_AUTHORIZATIONS[authorization.authorizationId];
  if (!admitted) {
    throw new Error(`authorization.authorizationId is not admitted: ${authorization.authorizationId}`);
  }
  equal(authorization.jobId, admitted.jobId, 'authorization.jobId');
  equal(authorization.expiresAt, admitted.expiresAt, 'authorization.expiresAt');

  exactKeys(
    authorization.bridge,
    [
      'repository', 'revision', 'signerPath', 'signerGitBlob', 'specPath',
      'specGitBlob', 'enginePublicKeyPath', 'enginePublicKeyGitBlob', 'queuePath',
    ],
    'bridge',
  );
  equal(authorization.bridge.repository, BRIDGE_REPOSITORY, 'bridge.repository');
  equal(authorization.bridge.revision, admitted.bridgeRevision, 'bridge.revision');
  equal(authorization.bridge.signerPath, 'cloud/sign-nemo-v3-job.mjs', 'bridge.signerPath');
  equal(authorization.bridge.signerGitBlob, admitted.signerGitBlob, 'bridge.signerGitBlob');
  equal(authorization.bridge.specPath, admitted.specPath, 'bridge.specPath');
  equal(authorization.bridge.specGitBlob, admitted.specGitBlob, 'bridge.specGitBlob');
  equal(authorization.bridge.enginePublicKeyPath, 'keys/engine_pubkey.json', 'bridge.enginePublicKeyPath');
  equal(authorization.bridge.enginePublicKeyGitBlob, ENGINE_PUBLIC_KEY_GIT_BLOB, 'bridge.enginePublicKeyGitBlob');
  equal(authorization.bridge.queuePath, admitted.queuePath, 'bridge.queuePath');

  const payloadFields = [
    'type', 'canonicalSha256', 'sourceRepository', 'sourceRevision',
    'baseRepository', 'baseRevision', 'requiredPassRate', 'maxDegenerateRate',
    'automaticRetry', 'publishCandidate',
  ];
  if (admitted.ownerDispatch) payloadFields.push('ownerDispatch');
  exactKeys(authorization.payload, payloadFields, 'payload');
  equal(authorization.payload.type, PAYLOAD_TYPE, 'payload.type');
  equal(authorization.payload.canonicalSha256, admitted.canonicalSha256, 'payload.canonicalSha256');
  equal(authorization.payload.sourceRepository, 'szl-holdings/a11oy', 'payload.sourceRepository');
  equal(authorization.payload.sourceRevision, admitted.sourceRevision, 'payload.sourceRevision');
  equal(authorization.payload.baseRepository, 'nvidia/NVIDIA-Nemotron-3-Nano-4B-BF16', 'payload.baseRepository');
  equal(authorization.payload.baseRevision, 'dfaf35de3e30f1867dd8dbc38a7fc9fb52d3914f', 'payload.baseRevision');
  equal(authorization.payload.requiredPassRate, 1, 'payload.requiredPassRate');
  equal(authorization.payload.maxDegenerateRate, 0, 'payload.maxDegenerateRate');
  equal(authorization.payload.automaticRetry, false, 'payload.automaticRetry');
  equal(authorization.payload.publishCandidate, false, 'payload.publishCandidate');
  if (admitted.ownerDispatch) {
    exactKeys(authorization.payload.ownerDispatch, Object.keys(admitted.ownerDispatch), 'payload.ownerDispatch');
    for (const [field, expected] of Object.entries(admitted.ownerDispatch)) {
      equal(authorization.payload.ownerDispatch[field], expected, `payload.ownerDispatch.${field}`);
    }
  }

  exactKeys(authorization.engine, ['keyId', 'publicKeySpkiBase64'], 'engine');
  equal(authorization.engine.keyId, ENGINE_KEY_ID, 'engine.keyId');
  equal(authorization.engine.publicKeySpkiBase64, ENGINE_PUBLIC_KEY_SPKI, 'engine.publicKeySpkiBase64');

  exactKeys(
    authorization.effects,
    [
      'signExactReviewedPayload', 'artifactOnly', 'crossRepositoryWrite', 'training',
      'candidateUpload', 'publication', 'deployment', 'promotion',
    ],
    'effects',
  );
  equal(authorization.effects.signExactReviewedPayload, true, 'effects.signExactReviewedPayload');
  equal(authorization.effects.artifactOnly, true, 'effects.artifactOnly');
  for (const field of [
    'crossRepositoryWrite',
    'training',
    'candidateUpload',
    'publication',
    'deployment',
    'promotion',
  ]) {
    equal(authorization.effects[field], false, `effects.${field}`);
  }
  const expires = Date.parse(authorization.expiresAt);
  if (!Number.isFinite(expires)) throw new Error('authorization.expiresAt is invalid');
  return authorization;
}

export function validateExactSpec(spec, authorization) {
  object(spec, 'spec');
  equal(spec.jobId, authorization.jobId, 'spec.jobId');
  equal(spec.kind, 'szl-nemo-governed-v3', 'spec.kind');
  equal(spec.expiresAt, authorization.expiresAt, 'spec.expiresAt');
  equal(spec.source.repoId, authorization.payload.sourceRepository, 'spec.source.repoId');
  equal(spec.source.revision, authorization.payload.sourceRevision, 'spec.source.revision');
  equal(spec.base.repoId, authorization.payload.baseRepository, 'spec.base.repoId');
  equal(spec.base.revision, authorization.payload.baseRevision, 'spec.base.revision');
  equal(spec.evaluation.requiredPassRate, authorization.payload.requiredPassRate, 'spec.evaluation.requiredPassRate');
  equal(spec.evaluation.maxDegenerateRate, authorization.payload.maxDegenerateRate, 'spec.evaluation.maxDegenerateRate');
  equal(spec.evaluation.requireExactRecordOrder, true, 'spec.evaluation.requireExactRecordOrder');
  equal(spec.outputs.publishCandidate, authorization.payload.publishCandidate, 'spec.outputs.publishCandidate');
  equal(spec.outputs.private, true, 'spec.outputs.private');
  equal(spec.dataset.rightsBasis, 'PROJECT_AUTHORED_SCENARIOS', 'spec.dataset.rightsBasis');
  equal(spec.dataset.holdouts.length, 3, 'spec.dataset.holdouts.length');
  equal(spec.gates.maxTemperatureC, 78, 'spec.gates.maxTemperatureC');
  equal(spec.gates.maxUtilizationPct, 15, 'spec.gates.maxUtilizationPct');
  if (authorization.payload.ownerDispatch) {
    exactKeys(
      spec.ownerDispatch,
      Object.keys(authorization.payload.ownerDispatch),
      'spec.ownerDispatch',
    );
    for (const [field, expected] of Object.entries(authorization.payload.ownerDispatch)) {
      equal(spec.ownerDispatch[field], expected, `spec.ownerDispatch.${field}`);
    }
    equal(spec.outputs.receiptsRepoId, authorization.payload.ownerDispatch.receiptsRepoId, 'spec.outputs.receiptsRepoId');
    equal(spec.lineage.automaticRetry, false, 'spec.lineage.automaticRetry');
    equal(spec.lineage.successorGeneration, 2, 'spec.lineage.successorGeneration');
  } else if (spec.ownerDispatch !== undefined) {
    throw new Error('spec.ownerDispatch is not admitted by this authorization');
  }
  return spec;
}

export function verifyExactEnvelope(envelope, spec, authorization) {
  object(envelope, 'envelope');
  equal(envelope.payloadType, authorization.payload.type, 'envelope.payloadType');
  equal(envelope.publicKeySpkiBase64, authorization.engine.publicKeySpkiBase64, 'envelope.publicKeySpkiBase64');
  if (!Array.isArray(envelope.signatures) || envelope.signatures.length !== 1) {
    throw new Error('envelope must contain exactly one signature');
  }
  const signatureEntry = object(envelope.signatures[0], 'envelope.signatures[0]');
  equal(signatureEntry.keyid, authorization.engine.keyId, 'signature keyId');

  const payloadBytes = decodeBase64(envelope.payload, 'envelope.payload');
  const canonicalBytes = Buffer.from(canonicalize(spec), 'utf8');
  if (!payloadBytes.equals(canonicalBytes)) {
    throw new Error('signed payload bytes differ from the canonical reviewed spec');
  }
  equal(sha256(payloadBytes), authorization.payload.canonicalSha256, 'canonical payload sha256');

  const publicKeyBytes = decodeBase64(envelope.publicKeySpkiBase64, 'envelope.publicKeySpkiBase64');
  const derivedKeyId = sha256(publicKeyBytes).slice(0, 16);
  equal(derivedKeyId, authorization.engine.keyId, 'derived engine keyId');
  const signature = decodeBase64(signatureEntry.sig, 'signature');
  const publicKey = createPublicKey({ key: publicKeyBytes, format: 'der', type: 'spki' });
  if (!verifySignature(null, pae(envelope.payloadType, payloadBytes), publicKey, signature)) {
    throw new Error('engine signature verification failed');
  }
  return {
    payloadSha256: sha256(payloadBytes),
    engineKeyId: derivedKeyId,
  };
}

export function verifyPinnedBridgeTree(bridgeRoot, authorization) {
  equal(git(bridgeRoot, 'rev-parse', 'HEAD'), authorization.bridge.revision, 'bridge revision');
  const pinned = [
    ['signer', authorization.bridge.signerPath, authorization.bridge.signerGitBlob],
    ['spec', authorization.bridge.specPath, authorization.bridge.specGitBlob],
    ['engine public key', authorization.bridge.enginePublicKeyPath, authorization.bridge.enginePublicKeyGitBlob],
  ];
  for (const [label, path, expected] of pinned) {
    equal(git(bridgeRoot, 'hash-object', path), expected, `${label} git blob`);
  }
}

export function verifyHandoff({ authorizationPath, bridgeRoot, outputRoot, now = new Date() }) {
  const authorizationBytes = readFileSync(authorizationPath);
  const authorization = validateAuthorization(JSON.parse(authorizationBytes.toString('utf8')));
  if (now.getTime() >= Date.parse(authorization.expiresAt)) {
    throw new Error(`authorization expired at ${authorization.expiresAt}`);
  }
  verifyPinnedBridgeTree(bridgeRoot, authorization);

  const specPath = join(bridgeRoot, authorization.bridge.specPath);
  const spec = validateExactSpec(JSON.parse(readFileSync(specPath, 'utf8')), authorization);
  const canonicalPayload = Buffer.from(canonicalize(spec), 'utf8');
  equal(sha256(canonicalPayload), authorization.payload.canonicalSha256, 'reviewed spec canonical sha256');

  const queuePath = join(bridgeRoot, authorization.bridge.queuePath);
  const envelopeBytes = readFileSync(queuePath);
  const envelope = JSON.parse(envelopeBytes.toString('utf8'));
  const verified = verifyExactEnvelope(envelope, spec, authorization);

  mkdirSync(outputRoot, { recursive: true });
  const exportedQueuePath = join(outputRoot, basename(queuePath));
  copyFileSync(queuePath, exportedQueuePath);
  const receipt = {
    schema: RECEIPT_SCHEMA,
    generatedAt: new Date().toISOString(),
    state: READY_STATE,
    authorization: {
      id: authorization.authorizationId,
      path: authorizationPath,
      sha256: sha256(authorizationBytes),
      expiresAt: authorization.expiresAt,
    },
    bridge: {
      repository: authorization.bridge.repository,
      revision: authorization.bridge.revision,
      signerPath: authorization.bridge.signerPath,
      signerGitBlob: authorization.bridge.signerGitBlob,
      specPath: authorization.bridge.specPath,
      specGitBlob: authorization.bridge.specGitBlob,
      queuePath: authorization.bridge.queuePath,
    },
    job: {
      id: authorization.jobId,
      payloadType: authorization.payload.type,
      payloadSha256: verified.payloadSha256,
      envelopeSha256: sha256(envelopeBytes),
      engineKeyId: verified.engineKeyId,
      sourceRepository: authorization.payload.sourceRepository,
      sourceRevision: authorization.payload.sourceRevision,
      baseRepository: authorization.payload.baseRepository,
      baseRevision: authorization.payload.baseRevision,
      requiredPassRate: authorization.payload.requiredPassRate,
      maxDegenerateRate: authorization.payload.maxDegenerateRate,
      publishCandidate: false,
      ...(authorization.payload.ownerDispatch
        ? { ownerDispatch: authorization.payload.ownerDispatch }
        : {}),
    },
    output: {
      artifactOnly: true,
      queueFile: basename(exportedQueuePath),
      crossRepositoryWrite: false,
    },
    secretBoundary: {
      credentialName: 'SZL_QUANT_SIGNING_KEY_PEM',
      valueRecorded: false,
      prefixRecorded: false,
      lengthRecorded: false,
      hashRecorded: false,
    },
    effects: {
      training: false,
      candidateUpload: false,
      publication: false,
      deployment: false,
      promotion: false,
    },
    nextExpectedState: 'QUEUED_AWAITING_GPU_RECEIPT',
    boundaries: [
      'This artifact authorizes exactly one preregistered job and no arbitrary payload.',
      'The workflow performs no training and writes no other repository.',
      'QUALIFIED_FOR_SEPARATE_PROMOTION_REVIEW remains a separate future gate.',
      'The signing key value is neither printed nor persisted.',
    ],
  };
  const receiptPath = join(outputRoot, 'nemo-v3-signing-handoff.receipt.json');
  writeFileSync(receiptPath, `${JSON.stringify(receipt, null, 2)}\n`);
  return { receipt, receiptPath, exportedQueuePath };
}

function parseArgs(argv) {
  const values = {};
  for (let index = 0; index < argv.length; index += 2) {
    const key = argv[index];
    const value = argv[index + 1];
    if (!key?.startsWith('--') || value === undefined) {
      throw new Error('usage: --authorization <file> --bridge-root <dir> --output-root <dir>');
    }
    values[key.slice(2)] = value;
  }
  return values;
}

export function main(argv = process.argv.slice(2)) {
  const args = parseArgs(argv);
  const authorizationPath = resolve(args.authorization ?? '');
  const bridgeRoot = resolve(args['bridge-root'] ?? '');
  const outputRoot = resolve(args['output-root'] ?? '');
  if (!authorizationPath || !bridgeRoot || !outputRoot) {
    throw new Error('authorization, bridge-root, and output-root are required');
  }
  const result = verifyHandoff({ authorizationPath, bridgeRoot, outputRoot });
  console.log(JSON.stringify({
    state: result.receipt.state,
    jobId: result.receipt.job.id,
    engineKeyId: result.receipt.job.engineKeyId,
    payloadSha256: result.receipt.job.payloadSha256,
    envelopeSha256: result.receipt.job.envelopeSha256,
    valueRecorded: result.receipt.secretBoundary.valueRecorded,
  }));
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  try {
    main();
  } catch (error) {
    console.error(`REFUSED: ${error.message}`);
    process.exit(1);
  }
}
