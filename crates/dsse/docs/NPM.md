# JavaScript and browser verification

The `npm/` package binds the public Rust DSSE verifier through WebAssembly.
Its API accepts raw envelope bytes and caller-selected Ed25519 keys, and returns
the native verifier's checked payload. The existing [Rust quick start](../README.md#quick-start)
and [standalone Sigstore-source comparison](SIGSTORE-JS-THRESHOLD.md) remain
separate consumers.

## Distribution identity

The npm package is `dsse` version `0.1.0`. The additive Rust source version
`0.1.3` supplies error serialization. The existing Rust `0.1.2` install pin and
its historical results remain unchanged. Registry metadata, artifact hashes
and provenance identify a published package; source versions alone do not
establish registry availability.

The package manifest declares Node 22.14 or later. Install a locally prepared
tarball in a consumer directory:

```bash
npm install ./dsse-0.1.0.tgz
```

This command selects the local file. A registry install instead needs the exact
published version and its checked artifact identity. The
[package entry](https://github.com/probityai/agent-evidence/blob/main/crates/dsse/npm/README.md) is the short install guide.

## Verify, then use the returned bytes

```ts
verify(
  envelope: Uint8Array,
  trusted_keys: readonly { public_key: Uint8Array; key_id?: string }[],
  threshold: number,
): {
  readonly payload_type: string;
  readonly payload: Uint8Array;
  readonly accepted_keys: readonly string[];
}
```

`envelope` contains the original DSSE JSON bytes. The Rust parser owns envelope
parsing; the JavaScript wrapper does not parse or normalize JSON. Each
`public_key` contains 32 raw Ed25519 public-key bytes, not PEM or DER. The caller
chooses the trusted keys and threshold. `key_id` is the caller's label, not a
grant of trust. An envelope's `keyid` only orders attempts; it cannot exclude a
trusted key.

The payload type and payload are those returned by `dsse::verify`. The binding
does not read them from the envelope again after verification. `accepted_keys`
preserves the native accepted-key list, rather than counting signature entries.
The result object and key list are frozen. The payload is a new, caller-owned
`Uint8Array`; its bytes remain mutable by that caller.

### A public reference fixture

Save this as `verify-example.mjs` in the installed consumer directory and run
`node verify-example.mjs`. The envelope is the unchanged `empty_body` case from
the [Go-produced reference fixtures](../vectors/cross_lang_signing.json). The
raw public key is the Ed25519 key in that file's `public_key_pem`; its test seed
is public. This demonstrates verification of a synthetic empty body.

```js
import assert from "node:assert/strict";
import { verify } from "dsse";

const key_id = "6a0b3c3b3cec7193b931661a269a55410ffdacc86b5c1d40fd3f107d4e9c6158";
const public_key = new Uint8Array(Buffer.from(
  "4d49b2502db1f70397cafa97052f21ba76f587535cf4e59d2e78de5a08d7aeae", "hex",
));
const envelope = new TextEncoder().encode(JSON.stringify({
  payloadType: "text/plain; charset=utf-8",
  payload: "",
  signatures: [{
    keyid: key_id,
    sig: "c6F2SRhnixYv7trNrArRVbFwZK555PTdvlt9hCD9L7SDmtpIamBZw+T5ogmr2grPHwIIUk4PlcLQaqPbKM2JDw==",
  }],
}));
const checked = verify(envelope, [{ public_key, key_id }], 1);
assert.equal(checked.payload_type, "text/plain; charset=utf-8");
assert.equal(checked.payload.byteLength, 0);
assert.deepEqual(checked.accepted_keys, [key_id]);
console.log("verified empty reference payload");
```

The example constructs an envelope from a known fixture. For a received
envelope, pass its received bytes directly to `verify`; do not use a JavaScript
parse/serialize step as an input-admission check.

## Browser initialization

The browser entry needs initialization before its synchronous verification API:

```js
import initialize, { verify, pae, DsseError } from "dsse/browser";

await initialize();
// Now call verify with envelope/key Uint8Array values, as above.
```

Serve the packaged JavaScript and adjacent `generated/dsse_bg.wasm` together.
The generated loader resolves the WASM asset relative to its own module. An
application that supplies the asset itself can pass
`initialize({ module_or_path: wasmURL })`, or a supported response, byte buffer
or `WebAssembly.Module`. The Node entry initializes its packaged WASM file
automatically. Neither entry contacts a signature service or key registry.

## Refusals and argument limits

`DsseError` extends `Error`. `variant`, `fields` and `message` preserve the
[native error enum](../src/error.rs), including its different field shapes:

| Native variant shape | JavaScript `fields` |
| --- | --- |
| Unit, such as `ZeroThreshold` or `NoSignatures` | `undefined` |
| Tuple string, such as `MalformedEnvelope` or `InvalidKey` | The original string |
| Struct, such as `ThresholdNotMet` | `{ accepted, threshold }` |
| Struct, such as `NonCanonicalBase64` | `{ field }` |
| Struct, such as `DuplicateKeyIdentity` | `{ first, second }` |

The discriminant is not replaced with a generic reason alias. Error variants
are not an exhaustive TypeScript union, matching the native non-exhaustive
enum. A signature refusal is different from a JavaScript transport error:

- Envelope, payload and key bytes must be `Uint8Array` values. Ordinary arrays
  and `DataView` values are not byte inputs.
- Threshold transport accepts integers from 0 through 4,294,967,295. Values
  outside that range, fractions, infinities and `NaN` throw `RangeError` before
  the call. Zero reaches the native verifier and yields `ZeroThreshold` for a
  well-formed envelope and valid keys.
- `payload_type` passed to `pae` and caller key labels must contain Unicode
  scalar values. Lone UTF-16 surrogates throw `TypeError` before UTF-8 conversion
  can replace them. The wrapper does not normalize valid strings.

The native verifier retains its canonical padded standard/URL-safe base64
rules, 1,024-entry cap and distinct-key threshold checks. It can skip an
unusable signature entry while another valid entry satisfies the policy;
malformed signature text is not silently converted into a valid signature.
See [the design and evidence](DESIGN.md) for exact refusal behavior and source
provenance. The wrapper supplies no signing, custom-verifier, KMS or certificate
validation API.

## Pre-authentication encoding

`pae(payload_type: string, payload: Uint8Array): Uint8Array` returns the native
DSSE PAE bytes. Lengths count UTF-8 bytes. This operation performs encoding,
not signature verification or envelope admission; an encoded value is not a
verification result.

Offline DSSE verification establishes signatures under selected keys. It does
not establish authorization, an event's occurrence or completeness, an effect,
Sigstore bundle validity, a Fulcio chain, a Rekor inclusion or a timestamp.

[Package entry](https://github.com/probityai/agent-evidence/blob/main/crates/dsse/npm/README.md) · [Rust documentation](../README.md#documentation) · [Changelog](../CHANGELOG.md)
