import { createHash, createPublicKey, KeyObject } from 'node:crypto';
import { loadSigstoreSource } from './native.mjs';

export const MAX_SIGNATURES = 1024;
let nativePromise;

export class VerificationError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'VerificationError';
    this.code = code;
  }
}

function refuse(code, message) {
  throw new VerificationError(code, message);
}

function decodeBase64(value, field) {
  if (typeof value !== 'string') refuse('malformed-envelope', `${field} must be a string`);
  const bytes = Buffer.from(value, 'base64');
  const standard = bytes.toString('base64');
  const url = standard.replaceAll('+', '-').replaceAll('/', '_');
  if (value !== standard && value !== url) {
    refuse('noncanonical-base64', `noncanonical base64: ${field}`);
  }
  return bytes;
}

function signatureEntry(entry) {
  if (!entry || typeof entry !== 'object' || Array.isArray(entry)) {
    refuse('malformed-envelope', 'signature entry must be an object');
  }
  const sig = entry.sig;
  const hint = entry.keyid ?? '';
  if (typeof sig !== 'string' || typeof hint !== 'string') {
    refuse('malformed-envelope', 'signature sig and keyid must be strings');
  }
  try {
    return { sig: decodeBase64(sig, 'signatures[].sig'), keyid: hint };
  } catch (error) {
    if (error.code === 'noncanonical-base64') return null;
    throw error;
  }
}

function envelopeFields(envelope) {
  if (!envelope || typeof envelope !== 'object' || Array.isArray(envelope)) {
    refuse('malformed-envelope', 'envelope must be an object');
  }
  return { payloadType: envelope.payloadType, encodedPayload: envelope.payload,
    signatures: envelope.signatures };
}

function checkSignatures(signatures) {
  if (!Array.isArray(signatures) || signatures.length === 0) {
    refuse('no-signatures', 'envelope must contain signatures');
  }
  if (signatures.length > MAX_SIGNATURES) {
    refuse('too-many-signatures', `signature count exceeds ${MAX_SIGNATURES}`);
  }
}

function snapshotEnvelope(envelope) {
  const { payloadType, encodedPayload, signatures } = envelopeFields(envelope);
  if (typeof payloadType !== 'string' || !payloadType) {
    refuse('empty-payload-type', 'payloadType must be a nonempty string');
  }
  checkSignatures(signatures);
  const payload = decodeBase64(encodedPayload, 'payload');
  const entries = signatures.map(signatureEntry).filter(entry => entry !== null);
  if (entries.length === 0) {
    refuse('noncanonical-base64', 'noncanonical base64: signatures[].sig');
  }
  return { payloadType, payload, entries };
}

function publicKey(item, index) {
  if (!item || typeof item !== 'object') refuse('invalid-key', `invalid trusted key: ${index}`);
  const material = item.key;
  const id = item.id;
  if (id !== undefined && typeof id !== 'string') {
    refuse('invalid-key', `trusted key ${index} id must be a string`);
  }
  let key;
  try {
    key = material instanceof KeyObject && material.type === 'public'
      ? material : createPublicKey(material);
  } catch {
    refuse('invalid-key', `invalid trusted key: ${index}`);
  }
  if (key.asymmetricKeyType !== 'ed25519') {
    refuse('unsupported-key', `trusted key ${index} is not Ed25519`);
  }
  const identity = `ed25519:${key.export({ type: 'spki', format: 'der' }).toString('hex')}`;
  return { key, identity, id, index };
}

function countableKeys(keys, threshold) {
  if (!Array.isArray(keys)) refuse('invalid-key', 'trusted keys must be an array');
  const normalized = keys.map(publicKey);
  const labels = new Set();
  const identities = new Set();
  for (const key of normalized) {
    if (threshold > 1) checkDistinct(key, labels, identities);
    labels.add(key.id);
    identities.add(key.identity);
  }
  // A threshold of one needs no label. Aliases still report only one identity.
  return normalized.filter((key, index) =>
    normalized.findIndex(candidate => candidate.identity === key.identity) === index);
}

function checkDistinct(key, labels, identities) {
  if (typeof key.id !== 'string' || !key.id) {
    refuse('unidentified-key', `trusted key ${key.index} needs a nonempty id`);
  }
  if (labels.has(key.id)) refuse('duplicate-key-id', `duplicate trusted key id: ${key.id}`);
  if (identities.has(key.identity)) {
    refuse('duplicate-key-identity', `duplicate trusted key identity: ${key.index}`);
  }
}

function keyAccepts(key, snapshot, NativeContent) {
  const ordered = [...snapshot.entries].sort((a, b) =>
    Number(b.keyid === key.id) - Number(a.keyid === key.id));
  return ordered.some(entry => new NativeContent({
    payloadType: snapshot.payloadType,
    payload: snapshot.payload,
    signatures: [entry],
  }).verifySignature(key.key));
}

/**
 * Verify an offline Ed25519 DSSE envelope using pinned native Sigstore checks.
 *
 * Each trusted key can contribute once. At thresholds above one, labels and
 * actual SPKI key identities must both be distinct. Unauthenticated keyid only
 * orders attempts. Invalid signature encodings are skipped; an invalid payload
 * encoding is refused. The result carries the same decoded bytes used by the
 * native verifier, and the envelope is never read again after the snapshot.
 *
 * @param {object} envelope - DSSE object with payloadType, payload and signatures.
 * @param {Array<{id?: string, key: string|KeyObject}>} keys - Consumer-selected
 *     trusted Ed25519 public keys. Their authority is an external policy input.
 * @param {number} threshold - Positive integer count of distinct trusted keys.
 * @returns {Promise<{payloadType: string, payload: Buffer, acceptedKeys: string[]}>}
 *     Only authenticated bytes and the distinct keys which accepted them.
 * @throws {VerificationError} With a stable code and message on a refused input.
 */
export async function verifyThreshold(envelope, keys, threshold) {
  if (!Number.isSafeInteger(threshold) || threshold < 1) {
    refuse('invalid-threshold', 'threshold must be a positive safe integer');
  }
  const snapshot = snapshotEnvelope(envelope);
  const trusted = countableKeys(keys, threshold);
  const loaded = await (nativePromise ??= loadSigstoreSource());
  const accepted = trusted.filter(key =>
    keyAccepts(key, snapshot, loaded.DSSESignatureContent));
  if (accepted.length < threshold) {
    refuse('threshold-not-met', `threshold not met: ${accepted.length} accepted, ${threshold} required`);
  }
  return {
    payloadType: snapshot.payloadType,
    payload: snapshot.payload,
    acceptedKeys: accepted.map(key => key.id || `#${key.index}`),
    acceptedIdentities: accepted.map(key => createHash('sha256').update(key.identity).digest('hex')),
  };
}
