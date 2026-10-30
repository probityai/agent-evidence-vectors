import { createHash } from 'node:crypto';
import { writeFile } from 'node:fs/promises';
import { fixtureSigner, signedEnvelope } from './fixtures.mjs';
import { loadSigstoreSource } from './native.mjs';

const native = await loadSigstoreSource();
const a = fixtureSigner(1, 'key-a');
const b = fixtureSigner(2, 'key-b');
const stranger = fixtureSigner(9, 'stranger');
const baseline = signedEnvelope(native, [a, b]);
const clone = value => structuredClone(value);
const key = value => ({ id: value.id, public_hex: value.key.export({ type: 'spki', format: 'der' }).subarray(12).toString('hex') });
const accepted = ['key-a', 'key-b'];
const rows = [];

function record(id, envelope, keys, threshold, jsCode = null, jsMessage = null, rustMessage = null, acceptedKeys = []) {
  rows.push({ id, envelope, trusted_keys: keys.map(key), threshold,
    expected: { decision: jsCode ? 'refused' : 'verified', js_code: jsCode,
      js_message: jsMessage, rust_message: rustMessage, accepted_keys: acceptedKeys } });
}
function thresholdFailure(id, envelope, count, required = 2) {
  record(id, envelope, [a, b], required, 'threshold-not-met',
    `threshold not met: ${count} accepted, ${required} required`,
    `signature threshold not met: ${count} distinct trusted key(s) accepted, ${required} required`);
}

record('two-distinct-keys', baseline, [a, b], 2, null, null, null, accepted);
for (const hint of ['wrong', '']) {
  const value = clone(baseline);
  value.signatures.forEach(signature => { signature.keyid = hint; });
  record(`untrusted-hint-${hint || 'empty'}`, value, [a, b], 2, null, null, null, accepted);
}
const repeated = signedEnvelope(native, [a]);
repeated.signatures.push(clone(repeated.signatures[0]));
thresholdFailure('duplicate-signature-entry', repeated, 1);
record('same-key-two-labels', baseline, [a, { ...a, id: 'alias' }], 2,
  'duplicate-key-identity', 'duplicate trusted key identity: 1', 'keys #0 and #1 have the same key identity');
record('same-label-two-keys', baseline, [a, { ...b, id: 'key-a' }], 2,
  'duplicate-key-id', 'duplicate trusted key id: key-a', 'two supplied keys report key_id "key-a"; a threshold cannot count them as distinct');
const extra = signedEnvelope(native, [stranger, a, b]);
extra.signatures.unshift({ sig: '!!!' }, { sig: 'AAAA' });
record('skip-extra-invalid-entries', extra, [a, b], 2, null, null, null, accepted);
thresholdFailure('changed-payload', { ...clone(baseline), payload: Buffer.from('changed').toString('base64') }, 0);
thresholdFailure('changed-type', { ...clone(baseline), payloadType: 'changed' }, 0);
thresholdFailure('signature-over-base64-text', signedEnvelope(native, [a, b], baseline.payloadType, Buffer.from(baseline.payload)), 0);
// Keep the original encoded payload while using signatures over its base64 text.
rows.at(-1).envelope.payload = baseline.payload;
thresholdFailure('wrong-length-signatures', { ...clone(baseline), signatures: [{ sig: 'AAAA' }] }, 0);
record('only-malformed-signatures', { ...clone(baseline), signatures: [{ sig: '!!!' }] }, [a, b], 2,
  'noncanonical-base64', 'noncanonical base64: signatures[].sig', 'signatures[].sig is not canonical base64 in either the standard or URL-safe alphabet');
record('noncanonical-payload', { ...clone(baseline), payload: 'eB==' }, [a, b], 2,
  'noncanonical-base64', 'noncanonical base64: payload', 'payload is not canonical base64 in either the standard or URL-safe alphabet');
record('empty-payload-type', { ...clone(baseline), payloadType: '' }, [a, b], 2,
  'empty-payload-type', 'payloadType must be a nonempty string', 'payloadType is empty; a DSSE envelope must name the type its payload is');
record('no-signatures', { ...clone(baseline), signatures: [] }, [a, b], 2,
  'no-signatures', 'envelope must contain signatures', 'envelope carries no signatures; the schema requires at least one');
record('zero-threshold', baseline, [a, b], 0,
  'invalid-threshold', 'threshold must be a positive safe integer', 'a threshold of zero accepts an unsigned envelope');
thresholdFailure('threshold-above-key-count', baseline, 2, 3);
const body = {
  schema: 'probity.sigstore-js-dsse-controls.v1',
  generated_by: 'node generate-cases.mjs; deterministic published test seeds 1, 2 and 9',
  role: 'Authored finite consumer controls, not publisher fixtures or a research population.',
  native_revision: native.sourceRevision,
  payload_sha256: createHash('sha256').update(Buffer.from(baseline.payload, 'base64')).digest('hex'),
  cases: rows,
};
await writeFile(new URL('./cases.json', import.meta.url), `${JSON.stringify(body, null, 2)}\n`);
console.log(`generated ${rows.length} separately identified finite controls`);
