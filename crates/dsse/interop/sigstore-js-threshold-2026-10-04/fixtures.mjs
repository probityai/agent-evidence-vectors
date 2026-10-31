import { createPrivateKey, createPublicKey, sign } from 'node:crypto';
import { readFile } from 'node:fs/promises';

export async function referenceFixtures() {
  return JSON.parse(await readFile(new URL('../../vectors/cross_lang_signing.json', import.meta.url), 'utf8'));
}

// Published deterministic test material. Never use these keys for live records.
export function fixtureSigner(seed, id) {
  const prefix = Buffer.from('302e020100300506032b657004220420', 'hex');
  const key = createPrivateKey({ key: Buffer.concat([prefix, Buffer.alloc(32, seed)]), type: 'pkcs8', format: 'der' });
  return { id, privateKey: key, key: createPublicKey(key) };
}

export function signedEnvelope(native, signers, payloadType = 'application/vnd.example+json', payload = Buffer.from('{"a":1}')) {
  const pae = native.preAuthEncoding(payloadType, payload);
  return {
    payloadType,
    payload: payload.toString('base64'),
    signatures: signers.map(key => ({ keyid: key.id, sig: sign(null, pae, key.privateKey).toString('base64') })),
  };
}
