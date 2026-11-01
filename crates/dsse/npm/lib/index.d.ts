/** A caller-supplied public key. Its optional identifier creates no trust. */
export interface TrustedKey {
  readonly public_key: Uint8Array;
  readonly key_id?: string;
}

/** The exact bytes returned by the native verifier, plus authenticated metadata. */
export interface VerifiedPayload {
  readonly payload_type: string;
  readonly payload: Uint8Array;
  readonly accepted_keys: readonly string[];
}

/** Native Error data: struct fields, a tuple string, or undefined for a unit variant. */
export class DsseError extends Error {
  readonly variant: string;
  readonly fields: unknown;
  constructor(variant: string, fields: unknown, message: string);
}

/** Verify an Ed25519 threshold. Native refusals throw DsseError. */
export function verify(envelope: Uint8Array, trusted_keys: readonly TrustedKey[], threshold: number): VerifiedPayload;

/** Return the native pre-authentication encoding without verifying a signature. */
export function pae(payload_type: string, payload: Uint8Array): Uint8Array;
