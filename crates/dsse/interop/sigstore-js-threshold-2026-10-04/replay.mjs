import assert from 'node:assert/strict';
import { createHash, createPublicKey } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';
import { verifyThreshold } from './consumer.mjs';
import { referenceFixtures } from './fixtures.mjs';
import { SIGSTORE_REVISION, loadSigstoreSource } from './native.mjs';

const [output, ...extra] = process.argv.slice(2);
if (!output || extra.length) throw new Error('usage: node replay.mjs REPORT.json');
// Invalidate a prior report before any input can fail.
await writeFile(output, '');
const input = await readFile(new URL('./cases.json', import.meta.url));
const controls = JSON.parse(input);
const native = await loadSigstoreSource();
const fixtures = await referenceFixtures();
const rows = [];
for (const fixture of fixtures.fixtures) {
  const verified = await verifyThreshold(fixture.envelope,
    [{ id: fixtures.key_id, key: fixtures.public_key_pem }], 1);
  assert.deepEqual(verified.payload, Buffer.from(fixture.canonical_b64, 'base64'));
  assert.deepEqual(native.preAuthEncoding(verified.payloadType, verified.payload), Buffer.from(fixture.pae_b64, 'base64'));
  rows.push({ id: fixture.name, origin: 'unchanged-reference-Go-fixture', decision: 'verified', acceptedKeys: verified.acceptedKeys });
}
for (const row of controls.cases) {
  const keys = row.trusted_keys.map(key => ({ id: key.id, key: createPublicKey({
    key: Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), Buffer.from(key.public_hex, 'hex')]),
    type: 'spki', format: 'der',
  }) }));
  let result;
  try {
    const verified = await verifyThreshold(row.envelope, keys, row.threshold);
    result = { id: row.id, origin: 'authored-finite-control', decision: 'verified', acceptedKeys: verified.acceptedKeys };
  } catch (error) {
    result = { id: row.id, origin: 'authored-finite-control', decision: 'refused', code: error.code, message: error.message };
  }
  assert.equal(result.decision, row.expected.decision, row.id);
  if (result.decision === 'verified') assert.deepEqual(result.acceptedKeys, row.expected.accepted_keys, row.id);
  else {
    assert.equal(result.code, row.expected.js_code, row.id);
    assert.equal(result.message, row.expected.js_message, row.id);
  }
  rows.push(result);
}
const report = {
  schema: 'probity.sigstore-js-offline-replay.v1',
  sourceRevision: SIGSTORE_REVISION,
  runtime: process.version,
  implementation: 'Pinned Sigstore source functions plus owned threshold policy; not npm package installation.',
  controlSHA256: createHash('sha256').update(input).digest('hex'),
  referenceFixtureSHA256: createHash('sha256').update(await readFile(new URL('../../vectors/cross_lang_signing.json', import.meta.url))).digest('hex'),
  referenceFixtureCount: fixtures.fixtures.length,
  authoredControlCount: controls.cases.length,
  custody: 'Author-operated PEER; public test keys.',
  authorityPolicy: 'Explicit supplied trusted keys; key authority is not established by signatures.',
  nativeTaskState: null,
  effectEvidence: null,
  publicationDecision: null,
  unsupported: ['Sigstore bundle/certificates/tlog/TSA', 'key authority', 'native agent task', 'target effect', 'consumer publication', 'outside operator'],
  prospectiveEightTaskRun: 'not-started',
  rows,
};
await writeFile(output, `${JSON.stringify(report, null, 2)}\n`);
console.log(`replayed ${fixtures.fixtures.length} unchanged Go fixtures and ${controls.cases.length} finite controls`);
