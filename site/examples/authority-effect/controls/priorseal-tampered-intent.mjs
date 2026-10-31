// Review-only local control. No change to the pinned producer or reader files.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { bindEnvelope, recoverAuthorizer } from './examples/open-evidence-lab-exact-call-matrix-v1/reader.mjs';
import { verifyAuthorization } from './src/index.mjs';
import { hashJson } from './src/domain/canonical-json.mjs';

const root = './examples/open-evidence-lab-exact-call-matrix-v1/fixture/';
const source = JSON.parse(readFileSync(root + 'signed-authorization.json', 'utf8'));
const original = source.authorization;
const originalCheck = await verifyAuthorization(original, { now: original.notBefore });
assert.equal(originalCheck.valid, true);
const tampered = structuredClone(original);
const observed = JSON.parse(readFileSync(root + 'observed/case-00-exact-call-observed-match.json', 'utf8'));
tampered.intent.callTarget = '0x2222222222222222222222222222222222222222';
observed.target = tampered.intent.callTarget;
// The producer's rule sorts JS string keys and uses JSON.stringify for scalars.
// This control has only ASCII fixture keys and values and bounded integers. It
// does not qualify that custom rule as a general RFC 8785 implementation.
const canonical = (value) => {
  if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']';
  if (value !== null && typeof value === 'object')
    return '{' + Object.keys(value).sort().map(k => JSON.stringify(k) + ':' + canonical(value[k])).join(',') + '}';
  return JSON.stringify(value);
};
const preimage = (intent) => Object.fromEntries(Object.entries(intent).filter(([key]) => key !== 'intentHash'));
const ownHash = (intent) => createHash('sha256').update(canonical(preimage(intent))).digest('hex');
assert.equal(ownHash(original.intent), original.intentHash);
assert.equal(ownHash(original.intent), hashJson(preimage(original.intent)));
assert.equal(ownHash(tampered.intent), hashJson(preimage(tampered.intent)));
assert.notEqual(ownHash(tampered.intent), original.intentHash);
assert.equal(tampered.intentHash, original.intentHash);
assert.equal(tampered.intent.intentHash, original.intent.intentHash);
assert.equal(tampered.signature, original.signature);
const recovered = await recoverAuthorizer(tampered);
const bound = bindEnvelope(tampered.intent, observed);
const producer = await verifyAuthorization(tampered, { now: original.notBefore });
assert.equal(recovered.matchesDeclaredAuthorizer, true);
assert.equal(bound.bound, true);
assert.equal(producer.valid, false);
assert.equal(producer.code, 'INVALID_AUTHORIZATION');
console.log(JSON.stringify({schema:'probity.priorseal-tampered-intent-control/v1',
  commitmentRule:'SHA-256 over producer sorted compact JSON, excluding nested intentHash',
  canonicalizationScope:'ASCII fixture fields only; not general JCS qualification',
  declaredCommitment:original.intentHash, originalRecomputedCommitment:ownHash(original.intent),
  tamperedRecomputedCommitment:ownHash(tampered.intent), signatureUnchanged:true,
  declaredHashUnchanged:true, standaloneRecovery:recovered, standaloneBinding:bound,
  producerAuthorization:producer,
  originalProducerAuthorization:originalCheck,
  scope:'Synthetic fixture; this exposes the standalone reader preimage gap, not a producer verifier bypass'
}, null, 2));
