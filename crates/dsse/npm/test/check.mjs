export function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function normalized(value) {
  if (Array.isArray(value)) return value.map(normalized);
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, normalized(value[key])]));
  }
  return value;
}

export function same(actual, expected, label) {
  assert(JSON.stringify(normalized(actual)) === JSON.stringify(normalized(expected)), `${label}: ${JSON.stringify(actual)} != ${JSON.stringify(expected)}`);
}

export function keyInputs(item) {
  return item.trusted_keys.map((key) => ({ ...key, public_key: new Uint8Array(key.public_key) }));
}

export function checkedPayload(value, label) {
  assert(Object.isFrozen(value), `${label}: verified object is mutable`);
  assert(value.payload instanceof Uint8Array, `${label}: verified payload is not a byte view`);
  assert(Array.isArray(value.accepted_keys) && Object.isFrozen(value.accepted_keys), `${label}: accepted key list is not frozen`);
  return { payload_type: value.payload_type, payload: [...value.payload], accepted_keys: [...value.accepted_keys] };
}

export function checkCase(api, item, expected) {
  let value;
  try {
    value = item.operation === "verify"
      ? api.verify(new Uint8Array(item.envelope), keyInputs(item), item.threshold)
      : api.pae(item.payload_type, new Uint8Array(item.payload));
  } catch (error) {
    assert(!expected.ok, `${item.id}: native accepts, installed module refuses`);
    assert(error instanceof Error && error instanceof api.DsseError, `${item.id}: refusal lost Error/DsseError prototype`);
    assert(error.name === "DsseError" && typeof error.stack === "string" && error.stack.length > 0, `${item.id}: error name or stack differs`);
    if (error.fields !== null && typeof error.fields === "object") assert(Object.isFrozen(error.fields), `${item.id}: native struct fields are mutable`);
    same({ variant: error.variant, fields: error.fields, message: error.message }, expected.error, `${item.id}: exact native refusal`);
    if (item.retainedDecision) assert(item.retainedDecision === "refused", `${item.id}: retained accepted case refused`);
    if (item.retainedMessage) assert(error.message === item.retainedMessage, `${item.id}: retained native message differs`);
    return "refused";
  }
  assert(expected.ok, `${item.id}: native refuses, installed module accepts`);
  if (item.operation === "verify") {
    const actual = checkedPayload(value, item.id);
    same(actual, expected.verified, `${item.id}: exact native verified result`);
    if (item.retainedVerified) same(actual, item.retainedVerified, `${item.id}: retained Go verified bytes`);
    if (item.retainedDecision) assert(item.retainedDecision === "verified", `${item.id}: retained refusal accepted`);
    if (item.retainedAcceptedKeys) same(actual.accepted_keys, item.retainedAcceptedKeys, `${item.id}: retained distinct keys`);
  } else {
    assert(value instanceof Uint8Array, `${item.id}: PAE result is not a byte view`);
    same([...value], expected.output, `${item.id}: exact native PAE bytes`);
    if (item.retainedOutput) same([...value], item.retainedOutput, `${item.id}: retained independent PAE bytes`);
  }
  return "accepted";
}

export function checkInputContract(api, item, expected) {
  assert(item.operation === "verify" && expected.ok && expected.verified.payload.length > 0, "Input controls need a verified nonempty reference payload");
  const envelope = new Uint8Array(item.envelope);
  const keys = keyInputs(item);
  function refuse(call, Constructor, label) {
    let caught;
    try { call(); } catch (error) { caught = error; }
    assert(caught instanceof Constructor && !(caught instanceof api.DsseError), `${label}: argument was coerced or relabeled`);
  }
  const spoof = { [Symbol.toStringTag]: "Uint8Array", buffer: new ArrayBuffer(2), byteOffset: 0, byteLength: 2 };
  const proxy = new Proxy(envelope, { get() { throw new Error("Proxy input was inspected"); } });
  const wrongBytes = [undefined, null, "{}", [123, 125], { a: 1 }, new ArrayBuffer(2), new DataView(new ArrayBuffer(2)), new Uint16Array([1]), new Int8Array([1]), new Uint8ClampedArray([1]), spoof, Object.create(Uint8Array.prototype), proxy];
  for (const value of wrongBytes) {
    refuse(() => api.verify(value, keys, 1), TypeError, "envelope raw type");
    refuse(() => api.verify(envelope, [{ public_key: value }], 1), TypeError, "key raw type");
    refuse(() => api.pae("t", value), TypeError, "payload raw type");
  }
  for (const value of [undefined, null, {}, "[]", new Set()]) refuse(() => api.verify(envelope, value, 1), TypeError, "key set type");
  for (const value of [undefined, null, "1", 1n, {}, { valueOf() { throw new Error("threshold coerced"); } }]) refuse(() => api.verify(envelope, keys, value), TypeError, "threshold type");
  for (const value of [-1, 0.5, NaN, Infinity, -Infinity, 0x100000000, Number.MAX_SAFE_INTEGER]) refuse(() => api.verify(envelope, keys, value), RangeError, "threshold range");
  for (const value of [undefined, null, 1, {}, new String("t"), "\ud800", "\udc00", "x\ud800y", "\ud800a", "\ud800\ud800"]) {
    refuse(() => api.pae(value, new Uint8Array()), TypeError, "payload type scalar string");
    if (value !== undefined) refuse(() => api.verify(envelope, [{ public_key: keys[0].public_key, key_id: value }], 1), TypeError, "key label scalar string");
  }
  const raw = new Uint8Array(envelope.length + 2).fill(0xff);
  raw.set(envelope, 1);
  const view = raw.subarray(1, -1);
  same(checkedPayload(api.verify(view, keys, item.threshold), "subarray"), expected.verified, "intrinsic envelope extent");
  const shadowed = new Uint8Array(envelope);
  Object.defineProperties(shadowed, { length: { value: 0 }, byteLength: { value: 0 }, byteOffset: { value: 100 }, buffer: { value: new ArrayBuffer(1) }, [Symbol.toStringTag]: { value: "Int8Array" } });
  same(checkedPayload(api.verify(shadowed, keys, item.threshold), "shadowed"), expected.verified, "shadowed intrinsic extent");
  const shadowedKey = new Uint8Array(keys[0].public_key);
  Object.defineProperties(shadowedKey, { length: { value: 0 }, byteLength: { value: 0 }, byteOffset: { value: 100 }, buffer: { value: new ArrayBuffer(1) }, [Symbol.toStringTag]: { value: "Int8Array" } });
  same(checkedPayload(api.verify(envelope, [{ ...keys[0], public_key: shadowedKey }], item.threshold), "shadowed key"), expected.verified, "shadowed key extent");
  const payload = new Uint8Array([0, 255, 128, 65]);
  const pae = api.pae("t", payload);
  const paeBytes = [...pae];
  const shadowedPayload = new Uint8Array(payload);
  Object.defineProperties(shadowedPayload, { length: { value: 0 }, byteLength: { value: 0 }, byteOffset: { value: 100 }, buffer: { value: new ArrayBuffer(1) }, [Symbol.toStringTag]: { value: "Int8Array" } });
  same([...api.pae("t", shadowedPayload)], paeBytes, "shadowed PAE extent");
  assert(pae !== payload, "PAE output aliases its input object");
  pae.fill(0);
  same([...payload], [0, 255, 128, 65], "PAE output changed input bytes");
  same([...api.pae("t", payload)], paeBytes, "PAE output aliases retained WASM memory");
  const result = api.verify(envelope, keys, item.threshold);
  assert(result.payload !== envelope && result.payload !== keys[0].public_key, "Verified output aliases an input object");
  result.payload.fill(0);
  same([...envelope], item.envelope, "Verified output changed envelope bytes");
  same(checkedPayload(api.verify(envelope, keys, item.threshold), "owned output"), expected.verified, "Verified output aliases retained WASM memory");
  return { rawTypes: true, thresholds: true, scalarStrings: true, intrinsicExtent: true, outputOwnership: true };
}
