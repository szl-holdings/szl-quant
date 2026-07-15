# Activate CI (30-second owner step)

The automation token that created this repo has no `workflow` scope, so it
cannot write `.github/workflows/*` (this is the same hard wall documented
across the estate — stated honestly rather than worked around).

To activate CI:

```bash
git clone https://github.com/szl-holdings/szl-quant.git && cd szl-quant
mkdir -p .github/workflows
git mv scripts/ci.workflow.yml .github/workflows/ci.yml
git commit -m "ci: activate workflow (owner move — token lacks workflow scope)"
git push
```

Or in the GitHub UI: create `.github/workflows/ci.yml` with the contents of
`scripts/ci.workflow.yml`, then delete the scripts copy.

Until then, the same checks run locally:

```bash
npm test                                   # unit tests
node verify/verify.mjs --pubkey keys/engine_pubkey.json --dir receipts/
```
