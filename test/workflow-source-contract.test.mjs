import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const workflow = readFileSync(join(ROOT, '.github', 'workflows', 'scheduled-paper.yml'), 'utf8');

test('scheduled paper binds execution to the exact workflow event revision before signing or publication', () => {
  assert.match(workflow, /SOURCE_REVISION:\s*\$\{\{ github\.sha \}\}/);
  assert.match(workflow, /ref:\s*\$\{\{ env\.SOURCE_REVISION \}\}/);
  assert.match(workflow, /persist-credentials:\s*false/);
  assert.match(workflow, /test "\$\(git rev-parse HEAD\)" = "\$SOURCE_REVISION"/);

  const proof = workflow.indexOf('- name: Prove exact scheduled source');
  const signing = workflow.indexOf('- name: Materialize signing key');
  const publication = workflow.indexOf('- name: Append receipts to ledger branch');
  assert.ok(proof >= 0, 'exact-source proof step must exist');
  assert.ok(signing > proof, 'source identity must be proven before signing-key materialization');
  assert.ok(publication > proof, 'source identity must be proven before ledger publication');

  const checkouts = workflow.match(/uses:\s*actions\/checkout@/g) ?? [];
  assert.equal(checkouts.length, 1, 'scheduled lane must have one unambiguous source checkout');
});
