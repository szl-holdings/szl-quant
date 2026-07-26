# SZL-Nemo v3 exact engine-signing handoff

## Purpose

This repository already uses the engine private key in a protected GitHub Actions secret to sign doctrine-governed paper-research receipts. The public key pinned here is byte-identical to the engine key pinned by `szl-holdings/szl-gpu-bridge`.

The Nemo v3 handoff uses that existing trust root for **one exact preregistered job**. It is not a general CI signing API and it does not move the private key into another repository.

## Exact authorization

The only admitted authorization is:

```text
authorizations/nemo-v3-20260722-exact.json
```

It pins all of the following:

- authorization ID and single job ID;
- expiration time;
- exact `szl-gpu-bridge` commit;
- exact signer, jobspec, and engine-public-key Git blobs;
- exact DSSE payload type;
- canonical jobspec SHA-256;
- exact A11oy source revision;
- exact NVIDIA base revision;
- 100% required holdout pass rate;
- zero permitted degeneration;
- no automatic retry;
- candidate publication disabled;
- no training, deployment, promotion, or cross-repository write by the signer.

Changing any of those fields requires a new reviewed authorization and protected pull request.

## Two-stage workflow

### Pull request

The pull-request job is credentialless. It checks out the exact reviewed bridge revision, verifies the pinned Git blobs and canonical jobspec hash, runs adversarial DSSE tests, and checks workflow boundaries. No signing secret is referenced by an executing pull-request job.

### Protected main

Only the protected `main` push created by merging the reviewed change may run the signing job. The job:

1. checks out the exact pinned bridge commit;
2. materializes `SZL_QUANT_SIGNING_KEY_PEM` into a mode-0600 runner-temporary file;
3. runs the already reviewed bridge signer against the one pinned jobspec;
4. immediately removes the temporary key file;
5. independently verifies payload bytes, payload hash, public-key pin, key ID, signature, bridge revision, Git blobs, and prohibited effects;
6. uploads only the signed queue envelope and a bounded verification receipt.

The workflow has `contents: read`, no issue permission, no deployment permission, no identity token, no repository write, and no cross-repository token. It contains no `workflow_dispatch` input surface.

## Secret boundary

The artifact records only the configured credential name and these booleans:

- value recorded: `false`;
- prefix recorded: `false`;
- length recorded: `false`;
- hash recorded: `false`.

The private key is never printed, uploaded, committed, copied to the bridge repository, or included in the receipt. The public 16-hex key ID is not secret.

## Output is not execution

A successful handoff has state:

```text
ENGINE_SIGNED_QUEUE_ARTIFACT_READY_FOR_PROTECTED_IMPORT
```

That state means only that the exact reviewed jobspec has a valid engine DSSE envelope. It does **not** mean:

- the queue envelope has been merged into `szl-gpu-bridge`;
- the owner GPU host is online;
- training has started or completed;
- any holdout passed;
- an adapter exists;
- a candidate was uploaded, published, deployed, or promoted.

Importing the envelope into `szl-gpu-bridge` requires a separate protected pull request containing only the independently verified queue file. After merge, the bridge status controller must advance to `QUEUED_AWAITING_GPU_RECEIPT` before any execution claim is made.

## Terminal law

The owner host may execute at most one attempt. The result must remain either:

- `QUALIFIED_FOR_SEPARATE_PROMOTION_REVIEW`; or
- an honest terminal blocked/evaluation-failure state.

There is no automatic retry and no threshold weakening. Promotion remains a separate reviewed process.
