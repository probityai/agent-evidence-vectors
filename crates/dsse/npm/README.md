# dsse for JavaScript

Raw-byte DSSE Ed25519 threshold verification through the
[public Rust implementation](https://github.com/probityai/agent-evidence/tree/main/crates/dsse).
Verification returns the payload bytes that the native verifier checked.

## Install

The npm package is `dsse` version `0.1.0`, built from the public Rust verifier.
To install a locally built tarball with Node 22.14 or later:

```bash
npm install ./dsse-0.1.0.tgz
```

```js
import { readFile } from "node:fs/promises";
import { verify } from "dsse";

const envelope = new Uint8Array(await readFile("envelope.json"));
const public_key = new Uint8Array(await readFile("ed25519-public-key.bin"));
const checked = verify(envelope, [{ public_key, key_id: "release" }], 1);
console.log(checked.payload_type, checked.payload, checked.accepted_keys);
```

The public key is 32 raw Ed25519 bytes. The caller selects trusted keys; an
envelope's `keyid` is only a hint. Use `checked.payload` after verification,
rather than reading the envelope again.

`pae(payload_type, payload)` returns the native pre-authentication encoding; it
does not verify a signature. Native refusals throw `DsseError` with the original
`variant`, `fields` and message. Invalid JavaScript transport arguments throw
`TypeError` or `RangeError`.

The [full guide](https://github.com/probityai/agent-evidence/blob/main/crates/dsse/docs/NPM.md) has a
public test fixture, browser initialization, exact error shapes and transport
limits. This binding checks offline DSSE envelopes; it does not validate a
Sigstore bundle or establish authority, occurrence or a downstream effect.

Apache-2.0. See the [source documentation](https://github.com/probityai/agent-evidence/tree/main/crates/dsse#documentation).
