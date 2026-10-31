# jcs-admit

Admit raw JSON bytes before signing or hashing them. This package calls the same
Rust parser and RFC 8785 canonicalizer as the `jcs-admit` crate. It refuses
duplicate members and malformed raw strings before decoding can lose them.

The npm distribution is `jcs-admit` version `0.1.0`, built from the public Rust
core. To install a locally built tarball:

```sh
npm install ./jcs-admit-0.1.0.tgz
```

Node 22.14 or newer, ESM:

```js
import { admit, admit_ijson, JcsError } from "jcs-admit";

const bytes = new TextEncoder().encode('{"b":1,"a":2}');
console.log(new TextDecoder().decode(admit(bytes))); // {"a":2,"b":1}
```

`admit` preserves the native RFC 8785 defaults. `admit_ijson` explicitly applies
the native I-JSON safe-integer and noncharacter checks. Both take a `Uint8Array`
and return a new `Uint8Array`. Strings, arrays and parsed objects raise a
`TypeError`; there is no implicit decoding or JSON parsing in JavaScript.

Browser use initializes the same WebAssembly bytes:

```js
import initialize, { admit } from "jcs-admit/browser";
await initialize();
const canonical = admit(new TextEncoder().encode('{"b":1,"a":2}'));
```

Use a module-aware bundler or serve the package's modules and adjacent WASM file.
Node loads that artifact internally. There is no install script or runtime
dependency.

A native refusal is a `JcsError` and an `Error`. `error.variant` is the unchanged
Rust variant. `error.fields` preserves the native field names, values and byte
offsets; `error.message` is the native bounded display text.

```js
try {
  admit(new TextEncoder().encode('{"name":1,"name":2}'));
} catch (error) {
  if (!(error instanceof JcsError)) throw error;
  console.log(error.variant);     // DuplicateMember
  console.log(error.fields.name); // name
  console.log(error.fields.offset); // byte offset of the repeated opening quote
}
```

Canonicalization is one primitive. It does not establish a signature, an evidence
claim or a policy decision. See the [public source and build guide](https://github.com/probityai/agent-evidence/blob/main/crates/jcs-admit/docs/NPM.md)
for exact profiles, artifact identity, parity tests and release verification.
