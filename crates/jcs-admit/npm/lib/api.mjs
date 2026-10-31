import * as core from "../generated/jcs_admit.js";

const ByteArray = Uint8Array;
const typedArray = Object.getPrototypeOf(ByteArray.prototype);
const apply = Reflect.apply;
const intrinsic = (key) => Object.getOwnPropertyDescriptor(typedArray, key).get;
const arrayName = intrinsic(Symbol.toStringTag);
const arrayBuffer = intrinsic("buffer");
const arrayOffset = intrinsic("byteOffset");
const arrayLength = intrinsic("byteLength");

function localByteView(input) {
  // The intrinsic getter reads the typed-array brand, not an input's tag or
  // coercion hooks. Construct a local view of the same bytes without copying.
  if (apply(arrayName, input, []) !== "Uint8Array") {
    throw new TypeError("input must be a Uint8Array");
  }
  return new ByteArray(
    apply(arrayBuffer, input, []),
    apply(arrayOffset, input, []),
    apply(arrayLength, input, []),
  );
}

/** A native refusal, with its Rust discriminant and fields preserved. */
export class JcsError extends Error {
  constructor(variant, fields, message) {
    super(message);
    this.name = "JcsError";
    this.variant = variant;
    this.fields = Object.freeze({ ...fields });
  }
}

function invoke(admission, input) {
  const view = localByteView(input);
  try {
    return admission(view);
  } catch (error) {
    if (
      error !== null &&
      typeof error === "object" &&
      typeof error.variant === "string" &&
      typeof error.message === "string" &&
      error.fields !== null &&
      typeof error.fields === "object"
    ) {
      throw new JcsError(error.variant, error.fields, error.message);
    }
    // Wrong input type and unrelated runtime exceptions keep their own type.
    throw error;
  }
}

/** Canonicalize raw bytes using the Rust RFC 8785 default profile. */
export function admit(input) {
  return invoke(core.admit, input);
}

/** Apply the explicit Rust I-JSON tightening to raw bytes. */
export function admit_ijson(input) {
  return invoke(core.admit_ijson, input);
}
