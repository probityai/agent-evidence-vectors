const ByteArray = Uint8Array;
const typedArray = Object.getPrototypeOf(ByteArray.prototype);
const apply = Reflect.apply;
const intrinsic = (key) => Object.getOwnPropertyDescriptor(typedArray, key).get;
const arrayName = intrinsic(Symbol.toStringTag);
const arrayBuffer = intrinsic("buffer");
const arrayOffset = intrinsic("byteOffset");
const arrayLength = intrinsic("byteLength");
const characterAt = String.prototype.charCodeAt;

export function byteView(input) {
  // Read the real typed-array brand and extent, including across realms.
  if (apply(arrayName, input, []) !== "Uint8Array") {
    throw new TypeError("input must be a Uint8Array");
  }
  return new ByteArray(
    apply(arrayBuffer, input, []),
    apply(arrayOffset, input, []),
    apply(arrayLength, input, []),
  );
}

export function scalarString(value, field) {
  if (typeof value !== "string") throw new TypeError(`${field} must be a string`);
  // JS strings can contain lone UTF-16 surrogates. Refuse them before the
  // binding's UTF-8 conversion can replace them and change a key identifier.
  for (let index = 0; index < value.length; index += 1) {
    const code = apply(characterAt, value, [index]);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = apply(characterAt, value, [index + 1]);
      if (!(next >= 0xdc00 && next <= 0xdfff)) {
        throw new TypeError(`${field} must contain Unicode scalar values`);
      }
      index += 1;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      throw new TypeError(`${field} must contain Unicode scalar values`);
    }
  }
  return value;
}
