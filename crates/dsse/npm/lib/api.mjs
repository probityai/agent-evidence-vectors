import * as core from "../generated/dsse.js";
import { byteView, scalarString } from "./bytes.mjs";

const isArray = Array.isArray;
const from = Array.from;

/** A refusal with the native Rust discriminant, fields and display text. */
export class DsseError extends Error {
  constructor(variant, fields, message) {
    super(message);
    this.name = "DsseError";
    this.variant = variant;
    this.fields = fields !== null && typeof fields === "object"
      ? Object.freeze({ ...fields }) : fields;
  }
}

function trustedKeys(keys) {
  if (!isArray(keys)) throw new TypeError("trusted_keys must be an array");
  return from(keys, (key) => {
    if (key === null || typeof key !== "object") {
      throw new TypeError("each trusted key must be an object");
    }
    const public_key = from(byteView(key.public_key));
    const key_id = key.key_id;
    return key_id === undefined
      ? { public_key }
      : { public_key, key_id: scalarString(key_id, "key_id") };
  });
}

/** Verify Ed25519 signatures and return only the payload the native core checked. */
export function verify(envelope, trusted_keys, threshold) {
  if (typeof threshold !== "number") throw new TypeError("threshold must be a number");
  if (!Number.isInteger(threshold) || threshold < 0 || threshold > 0xffffffff) {
    throw new RangeError("threshold must be an integer from 0 through 4294967295");
  }
  const keys = trustedKeys(trusted_keys);
  const bytes = byteView(envelope);
  try {
    const checked = core.verify(bytes, keys, threshold);
    return Object.freeze({
      payload_type: checked.payload_type,
      payload: checked.payload,
      accepted_keys: Object.freeze(checked.accepted_keys),
    });
  } catch (error) {
    if (error !== null && typeof error === "object"
        && typeof error.variant === "string" && typeof error.message === "string") {
      throw new DsseError(error.variant, error.fields, error.message);
    }
    throw error;
  }
}

/** Return the native PAE bytes; this operation makes no verification claim. */
export function pae(payload_type, payload) {
  return core.pae(scalarString(payload_type, "payload_type"), byteView(payload));
}
