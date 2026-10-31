import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync } from 'node:crypto';
import { mkdtemp, readFile, rm, writeFile, mkdir, copyFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { describe, it } from 'node:test';
import { verifyThreshold, VerificationError, MAX_SIGNATURES } from './consumer.mjs';
import { loadSigstoreSource, SOURCE_HASHES } from './native.mjs';
import { fixtureSigner, referenceFixtures, signedEnvelope } from './fixtures.mjs';
import { parseUniqueJSON } from './json.mjs';

const native = await loadSigstoreSource();
const fixtures = await referenceFixtures();
const a = fixtureSigner(1, 'key-a');
const b = fixtureSigner(2, 'key-b');
const stranger = fixtureSigner(9, 'stranger');
const envelope = signedEnvelope(native, [a, b]);
const clone = value => structuredClone(value);

async function refuses(candidate, keys, threshold, code, message) {
  await assert.rejects(verifyThreshold(candidate, keys, threshold), error => {
    assert.ok(error instanceof VerificationError);
    assert.equal(error.code, code);
    assert.equal(error.message, message);
    return true;
  });
}

describe('SigstoreThresholdConsumer', () => {
  describe('PassingCases', () => {
    for (const fixture of fixtures.fixtures) {
      it(`verifies unchanged Go reference fixture ${fixture.name}`, async () => {
        const key = { id: fixtures.key_id, key: fixtures.public_key_pem };
        const result = await verifyThreshold(fixture.envelope, [key], 1);
        assert.equal(result.payloadType, fixture.payload_type);
        assert.deepEqual(result.payload, Buffer.from(fixture.canonical_b64, 'base64'));
        assert.deepEqual(native.preAuthEncoding(result.payloadType, result.payload), Buffer.from(fixture.pae_b64, 'base64'));
        assert.deepEqual(result.acceptedKeys, [fixtures.key_id]);
      });
    }
    it('counts two distinct native signatures under two actual keys', async () => {
      const result = await verifyThreshold(envelope, [a, b], 2);
      assert.deepEqual(result.acceptedKeys, ['key-a', 'key-b']);
      assert.equal(new Set(result.acceptedIdentities).size, 2);
      assert.equal(result.payload.toString(), '{"a":1}');
    });
    for (const hint of ['wrong-key', '', null, undefined]) {
      it(`keeps an unauthenticated hint ${String(hint)} from excluding a valid key`, async () => {
        const altered = clone(envelope);
        altered.signatures.forEach(entry => { entry.keyid = hint; });
        const result = await verifyThreshold(altered, [a, b], 2);
        assert.deepEqual(result.acceptedKeys, ['key-a', 'key-b']);
      });
    }
    it('skips malformed, invalid and untrusted signatures before a valid entry', async () => {
      const altered = signedEnvelope(native, [stranger, a]);
      altered.signatures.unshift({ sig: '!!!' }, { sig: 'AAAA' });
      const result = await verifyThreshold(altered, [a], 1);
      assert.deepEqual(result.acceptedKeys, ['key-a']);
    });
    it('preserves the native first-signature-only primitive distinction', async () => {
      const altered = signedEnvelope(native, [a]);
      altered.signatures.unshift({ sig: 'AAAA' });
      const raw = new native.DSSESignatureContent({ payloadType: altered.payloadType, payload: Buffer.from(altered.payload, 'base64'), signatures: altered.signatures.map(entry => ({ ...entry, sig: Buffer.from(entry.sig, 'base64') })) });
      assert.equal(raw.verifySignature(a.key), false);
      assert.deepEqual((await verifyThreshold(altered, [a], 1)).acceptedKeys, ['key-a']);
    });
    it('accepts both canonical padded base64 alphabets without rewriting payload bytes', async () => {
      const binary = signedEnvelope(native, [a], 'application/octet-stream', Buffer.from([255, 255]));
      binary.payload = binary.payload.replaceAll('+', '-').replaceAll('/', '_');
      binary.signatures[0].sig = binary.signatures[0].sig.replaceAll('+', '-').replaceAll('/', '_');
      assert.deepEqual((await verifyThreshold(binary, [a], 1)).payload, Buffer.from([255, 255]));
    });
    it('snapshots payload and container fields exactly once', async () => {
      const counts = { payload: 0, payloadType: 0, signatures: 0 };
      const source = signedEnvelope(native, [a]);
      const changing = Object.fromEntries(Object.keys(counts).map(key => [key, source[key]]));
      for (const key of Object.keys(counts)) Object.defineProperty(changing, key, { get() { counts[key]++; return counts[key] === 1 ? source[key] : 'changed'; } });
      const verified = await verifyThreshold(changing, [a], 1);
      assert.equal(verified.payload.toString(), '{"a":1}');
      assert.deepEqual(counts, { payload: 1, payloadType: 1, signatures: 1 });
    });
    it('reports a single key for signature and key aliases at threshold one', async () => {
      const single = signedEnvelope(native, [a]);
      single.signatures.push(clone(single.signatures[0]));
      const result = await verifyThreshold(single, [a, { id: 'alias', key: a.key }], 1);
      assert.deepEqual(result.acceptedKeys, ['key-a']);
    });
    it('accepts the finite signature cap and ignores unknown envelope fields', async () => {
      const single = signedEnvelope(native, [a]);
      single.signatures = Array.from({ length: MAX_SIGNATURES }, () => clone(single.signatures[0]));
      single.extension = { arbitrary: true };
      assert.deepEqual((await verifyThreshold(single, [a], 1)).acceptedKeys, ['key-a']);
    });
    it('uses a positional label when one trusted key has no id', async () => {
      assert.deepEqual((await verifyThreshold(envelope, [{ key: a.key }], 1)).acceptedKeys, ['#0']);
    });
    it('keeps repeated keys in separate JSON objects valid', () => {
      assert.deepEqual(parseUniqueJSON('{"a":{"k":1},"b":[{"k":2},{"k":3}]}'), { a: { k: 1 }, b: [{ k: 2 }, { k: 3 }] });
    });
  });
  describe('FailingCases', () => {
    for (const threshold of [0, -1, 1.5, true, '1', Number.NaN, Number.POSITIVE_INFINITY, Number.MAX_SAFE_INTEGER + 1]) {
      it(`refuses invalid threshold ${String(threshold)}`, () => refuses(envelope, [a, b], threshold, 'invalid-threshold', 'threshold must be a positive safe integer'));
    }
    for (const fixture of fixtures.fixtures) {
      it(`refuses changed type for reference fixture ${fixture.name}`, () => refuses({ ...fixture.envelope, payloadType: 'wrong-type' }, [{ id: fixtures.key_id, key: fixtures.public_key_pem }], 1, 'threshold-not-met', 'threshold not met: 0 accepted, 1 required'));
    }
    for (const payload of ['eA', 'eA=', 'eB==', 'eA==\n', 'eA== ', 'eA==garbage', '!!!!', 'AAAA=']) {
      it(`refuses noncanonical payload ${JSON.stringify(payload)}`, () => refuses({ ...envelope, payload }, [a], 1, 'noncanonical-base64', 'noncanonical base64: payload'));
    }
    it('refuses a repeated signature at threshold two', async () => {
      const single = signedEnvelope(native, [a]);
      single.signatures.push(clone(single.signatures[0]));
      await refuses(single, [a, b], 2, 'threshold-not-met', 'threshold not met: 1 accepted, 2 required');
    });
    it('refuses two labels for the same actual key', () => refuses(envelope, [a, { id: 'alias', key: a.key }], 2, 'duplicate-key-identity', 'duplicate trusted key identity: 1'));
    it('refuses two distinct keys with the same trusted label', () => refuses(envelope, [a, { id: 'key-a', key: b.key }], 2, 'duplicate-key-id', 'duplicate trusted key id: key-a'));
    it('refuses missing labels for threshold two', () => refuses(envelope, [{ key: a.key }, b], 2, 'unidentified-key', 'trusted key 0 needs a nonempty id'));
    it('refuses a non-string trusted label', () => refuses(envelope, [{ id: true, key: a.key }], 1, 'invalid-key', 'trusted key 0 id must be a string'));
    it('refuses changed payload bytes', () => refuses({ ...envelope, payload: Buffer.from('tampered').toString('base64') }, [a], 1, 'threshold-not-met', 'threshold not met: 0 accepted, 1 required'));
    it('refuses a threshold above the trusted key count', () => refuses(envelope, [a], 3, 'threshold-not-met', 'threshold not met: 1 accepted, 3 required'));
    it('refuses an empty trusted set', () => refuses(envelope, [], 1, 'threshold-not-met', 'threshold not met: 0 accepted, 1 required'));
    it('refuses an invalid trusted key', () => refuses(envelope, [{ id: 'bad', key: 'bad' }], 1, 'invalid-key', 'invalid trusted key: 0'));
    it('keeps ECDSA outside the selected Ed25519 consumer profile', () => refuses(envelope, [{ id: 'ec', key: generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).publicKey }], 1, 'unsupported-key', 'trusted key 0 is not Ed25519'));
    it('refuses a missing payload type', () => refuses({ ...envelope, payloadType: '' }, [a], 1, 'empty-payload-type', 'payloadType must be a nonempty string'));
    it('refuses a missing signature list', () => refuses({ ...envelope, signatures: [] }, [a], 1, 'no-signatures', 'envelope must contain signatures'));
    it('refuses only malformed signature encodings', () => refuses({ ...envelope, signatures: [{ sig: '!!!' }] }, [a], 1, 'noncanonical-base64', 'noncanonical base64: signatures[].sig'));
    it('treats a wrong-length decoded signature as threshold failure', () => refuses({ ...envelope, signatures: [{ sig: 'AAAA' }] }, [a], 1, 'threshold-not-met', 'threshold not met: 0 accepted, 1 required'));
    it('refuses a malformed signature object', () => refuses({ ...envelope, signatures: [null] }, [a], 1, 'malformed-envelope', 'signature entry must be an object'));
    it('refuses a non-string signature hint', () => refuses({ ...envelope, signatures: [{ sig: 'AAAA', keyid: 3 }] }, [a], 1, 'malformed-envelope', 'signature sig and keyid must be strings'));
    it('refuses the first signature beyond the finite cap', () => refuses({ ...envelope, signatures: Array(MAX_SIGNATURES + 1).fill(envelope.signatures[0]) }, [a], 1, 'too-many-signatures', 'signature count exceeds 1024'));
    for (const text of ['{"payload":"a","payload":"b"}', '{"payload":"a","payl\\u006fad":"b"}', '{"outer":{"id":1,"id":2}}']) {
      it(`refuses duplicate raw JSON members in ${text}`, () => assert.throws(() => parseUniqueJSON(text), { message: `duplicate JSON member: ${text.includes('outer') ? 'id' : 'payload'}` }));
    }
    it('refuses drift in a retained native source before loading code', async () => {
      const root = await mkdtemp(join(tmpdir(), 'dsse-native-source-'));
      try {
        for (const path of Object.keys(SOURCE_HASHES)) {
          await mkdir(join(root, path, '..'), { recursive: true });
          await copyFile(new URL(`./vendor/${path}`, import.meta.url), join(root, path));
        }
        const path = 'packages/core/src/dsse.ts';
        await writeFile(join(root, path), 'changed');
        await assert.rejects(loadSigstoreSource(root), { message: `native source hash differs: ${path}` });
      } finally { await rm(root, { recursive: true, force: true }); }
    });
  });
});

describe('SigstoreThresholdCLI', () => {
  it('runs a standalone installed consumer outside the source checkout', async () => {
    const evidence = process.env.SIGSTORE_INSTALL_EVIDENCE_DIR;
    if (evidence) await mkdir(evidence, { recursive: true });
    const root = await mkdtemp(join(evidence ?? tmpdir(), 'dsse-installed-'));
    const destination = join(root, 'consumer');
    const input = join(root, 'envelope.json');
    const policy = join(root, 'policy.json');
    const report = join(root, 'report.json');
    const installer = fileURLToPath(new URL('./install.mjs', import.meta.url));
    try {
      const install = spawnSync(process.execPath, [installer, destination], { encoding: 'utf8' });
      assert.equal(install.status, 0, install.stderr);
      await writeFile(input, JSON.stringify(fixtures.fixtures[0].envelope));
      await writeFile(policy, JSON.stringify({ threshold: 1, keys: [{ id: fixtures.key_id, key: fixtures.public_key_pem }] }));
      const result = spawnSync(process.execPath, [join(destination, 'cli.mjs'), input, policy, report], { encoding: 'utf8', cwd: root, env: { ...process.env, NODE_PATH: '' } });
      assert.equal(result.status, 0, result.stderr);
      const verified = JSON.parse(await readFile(report, 'utf8'));
      assert.equal(verified.payload, fixtures.fixtures[0].canonical_b64);
      assert.deepEqual(verified.acceptedKeys, [fixtures.key_id]);
      assert.equal(verified.sourceRevision, native.sourceRevision);
      const repeat = spawnSync(process.execPath, [installer, destination], { encoding: 'utf8' });
      assert.equal(repeat.status, 1);
      assert.match(repeat.stderr, /EEXIST/u);
    } finally { if (!evidence) await rm(root, { recursive: true, force: true }); }
  });
  it('writes verified bytes, then refuses with no stale passing report', async () => {
    const root = await mkdtemp(join(tmpdir(), 'dsse-cli-'));
    const input = join(root, 'envelope.json');
    const policy = join(root, 'policy.json');
    const report = join(root, 'report.json');
    const cli = fileURLToPath(new URL('./cli.mjs', import.meta.url));
    try {
      await writeFile(input, JSON.stringify(fixtures.fixtures[0].envelope));
      await writeFile(policy, JSON.stringify({ threshold: 1, keys: [{ id: fixtures.key_id, key: fixtures.public_key_pem }] }));
      let result = spawnSync(process.execPath, [cli, input, policy, report], { encoding: 'utf8' });
      assert.equal(result.status, 0, result.stderr);
      const verified = JSON.parse(await readFile(report, 'utf8'));
      assert.equal(verified.payload, fixtures.fixtures[0].canonical_b64);
      assert.equal(verified.policySHA256, createHash('sha256').update(await readFile(policy)).digest('hex'));
      await writeFile(input, JSON.stringify({ ...fixtures.fixtures[0].envelope, payloadType: 'changed' }));
      result = spawnSync(process.execPath, [cli, input, policy, report], { encoding: 'utf8' });
      assert.equal(result.status, 1);
      assert.match(result.stderr, /threshold not met: 0 accepted, 1 required/u);
      assert.equal(await readFile(report, 'utf8'), '');
      const before = await readFile(input);
      result = spawnSync(process.execPath, [cli, input, policy, input], { encoding: 'utf8' });
      assert.equal(result.status, 2);
      assert.match(result.stderr, /report path must differ from input paths/u);
      assert.deepEqual(await readFile(input), before);
    } finally { await rm(root, { recursive: true, force: true }); }
  });
});
