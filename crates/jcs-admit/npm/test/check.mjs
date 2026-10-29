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

export function checkCase(api, item, expected) {
  const input = item.repeat ? new Uint8Array(item.repeat.len).fill(item.repeat.byte) : new Uint8Array(item.bytes);
  if (item.repeat) {
    // The cap must use actual bytes even when an input shadows JS properties.
    Object.defineProperties(input, { length: { value: 0 }, byteLength: { value: 0 } });
  }
  const method = api[expected.profile];
  let result;
  try {
    result = method(input);
  } catch (error) {
    assert(!expected.ok, `${item.id}/${expected.profile}: native accepts, JS refuses`);
    assert(error instanceof Error && error instanceof api.JcsError, `${item.id}: refusal lost Error/JcsError prototype`);
    assert(error.name === "JcsError", `${item.id}: native field collided with Error.name`);
    assert(typeof error.stack === "string" && error.stack.length > 0, `${item.id}: stack missing`);
    assert(Object.isFrozen(error.fields), `${item.id}: fields are not frozen`);
    same({ variant: error.variant, fields: error.fields, message: error.message }, expected.error, `${item.id}/${expected.profile}: native refusal metadata`);
    return "refused";
  }
  assert(expected.ok, `${item.id}/${expected.profile}: native refuses, JS accepts`);
  assert(result instanceof Uint8Array && result !== input, `${item.id}: output must own a Uint8Array`);
  same([...result], expected.output, `${item.id}/${expected.profile}: native canonical bytes`);
  if (item.expectedProfiles?.includes(expected.profile)) same([...result], item.expected, `${item.id}: independently retained canonical bytes`);
  return "accepted";
}

export function checkInputContract(api) {
  const spoof = { [Symbol.toStringTag]: "Uint8Array", buffer: new ArrayBuffer(2), byteOffset: 0, byteLength: 2 };
  const proxy = new Proxy(new Uint8Array([123, 125]), { get() { throw new Error("Proxy input was inspected"); } });
  for (const input of [undefined, null, "{}", [123, 125], { a: 1 }, new ArrayBuffer(2), new DataView(new ArrayBuffer(2)), new Uint16Array([123, 125]), new Int8Array([123, 125]), new Uint8ClampedArray([123, 125]), spoof, Object.create(Uint8Array.prototype), proxy]) {
    let caught;
    try { api.admit(input); } catch (error) { caught = error; }
    assert(caught instanceof TypeError && !(caught instanceof api.JcsError), "Non-Uint8Array input was coerced or relabeled");
  }
  const raw = new Uint8Array([0xff, 0x7b, 0x7d, 0xff]);
  const view = raw.subarray(1, 3);
  const output = api.admit(view);
  same([...output], [0x7b, 0x7d], "byteOffset/byteLength preserved");
  output.fill(0);
  same([...view], [0x7b, 0x7d], "output did not alias input");
  same([...api.admit(view)], [0x7b, 0x7d], "output did not alias retained WASM memory");
  const shadowed = new Uint8Array([123, 125]);
  Object.defineProperties(shadowed, {
    length: { value: 1 }, byteLength: { value: 1 }, byteOffset: { value: 100 },
    buffer: { value: new ArrayBuffer(1) }, [Symbol.toStringTag]: { value: "Int8Array" },
  });
  same([...api.admit(shadowed)], [123, 125], "own properties did not replace the intrinsic byte view");
  const defaultValue = api.admit(new TextEncoder().encode("9007199254740993"));
  same([...defaultValue], [...new TextEncoder().encode("9007199254740992")], "RFC8785 default unchanged");
  let tightened;
  try { api.admit_ijson(new TextEncoder().encode("9007199254740993")); } catch (error) { tightened = error; }
  assert(tightened instanceof api.JcsError, "I-JSON tightening did not refuse unsafe integer");
  same({ variant: tightened.variant, fields: tightened.fields }, { variant: "UnsafeInteger", fields: { token: "9007199254740993" } }, "I-JSON is explicit; no reason alias");
}
