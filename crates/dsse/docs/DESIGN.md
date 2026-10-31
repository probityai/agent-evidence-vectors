# Design and evidence

What a DSSE signature covers, what this crate refuses and why, and how it is tested. The [README](../README.md) is the short version.

DSSE, the Dead Simple Signing Envelope, and the pre-authentication encoding its
signatures are computed over, as a Rust crate on its own: no in-toto dependency
and no Sigstore dependency. It depends on base64, serde and thiserror, plus an
ed25519 backend behind a feature you can turn off.

DSSE is the envelope the in-toto and Sigstore families sign inside. This crate
implements the envelope and nothing else, so a consumer who needs the envelope
does not take a product along with it.

## What a signature covers

A DSSE envelope carries a payload, a payload type that says how to read the
payload, and one or more signatures. A signature covers the pre-authentication
encoding of the payload type and the payload together, rather than the payload on
its own:

```text
PAE(type, body) = "DSSEv1" SP LEN(type) SP type SP LEN(body) SP body
LEN(s)          = ASCII decimal byte length of s, no leading zeros
```

The payload type sits inside the signed bytes, and that is what the encoding is
for. A verifier that checks the type beside the signature instead of inside it
will accept a signature minted for one attestation type as a signature for
another. That was CVE-2022-35929 in cosign. GitHub's advisory scored it 7.1 and
NVD scored it 9.8; the two scorers disagree, and there is no single agreed number.

## Verify, then read

```rust
use dsse::{sign, verify, Ed25519Signer};

let signer = Ed25519Signer::from_bytes(&seed)?.with_key_id("release-key");
let envelope = sign("application/vnd.in-toto+json", statement, &signer)?;

let verified = verify(&envelope, &[&signer.verifier()], 1)?;
// verified.payload is the exact bytes the signature covered.
```

Verification returns the payload bytes. The envelope is decoded once, that decode
builds the pre-image, and those same bytes come back. There is no second read,
because an implementation that returns to the envelope after verifying can be made
to hand the application bytes nobody signed. DSSE's protocol document requires
this in capitals, and this API gives you no way to do it.

## Bring your own signatures

The `ed25519` feature is on by default so that the crate works with no backend of
your own. To use anything else, an ECDSA key, a KMS, or a Sigstore signer, turn
the feature off and implement two traits:

```toml
dsse = { version = "0.1", default-features = false }
```

```rust
impl dsse::Verifier for MyKey {
    fn verify(&self, message: &[u8], signature: &[u8]) -> bool { /* ... */ }
    fn key_id(&self) -> Option<String> { Some(self.id.clone()) }
    fn key_identity(&self) -> Option<Vec<u8>> { Some(self.public_key_fingerprint.clone()) }
}
```

For a threshold above one, `key_identity` must identify the verification key,
not a caller-assigned label. Include the algorithm in that value. An opaque key
service can use an immutable key fingerprint. If it cannot identify a key, use
threshold one. The built-in Ed25519 verifier uses its public key bytes.

## What it refuses

The crate refuses six things that a permissive implementation accepts, and a test
fails against any implementation that allows one of them. DSSE's own reference
implementation allows four of the six.

| Refusal | Why |
|---|---|
| A length prefix counting characters | `LEN` is a byte length. For a payload type outside ASCII the two counts differ, and the signatures do not interoperate. |
| Base64 with non-zero trailing bits, or unpadded | `eA==` and `eB==` both decode to `x` under a lenient decoder. One signature over two envelope spellings is malleability. |
| An envelope with no signatures | The schema requires at least one. An empty list can meet no threshold. |
| A threshold of zero | It would accept an envelope that no trusted key signed. |
| A threshold met by counting signature entries | DSSE counts distinct keys. One valid signature copied five times is still one key, so each key contributes at most once. |
| A `keyid` treated as a filter | `keyid` sits outside the signed bytes, so an attacker can set it. Here it orders verification attempts and never excludes a key, and a wrong hint cannot withhold a valid verification. |

## Tests

`cargo test` runs 63 tests: 62 across eight files in `tests/`, and one doctest.
Two of those files load pinned vectors, five construct attacks, and one scans
every shipped file for names that must not be there.

The pinned files carry the test vector printed in DSSE's own protocol document,
and 11 cross-language fixtures built by the DSSE reference Go implementation,
github.com/secure-systems-lab/go-securesystemslib, over its own PAE pre-images and
signed with a published test key. Our PAE must reproduce each pre-image byte for
byte, each reference envelope must parse and verify through the public API, and our
signer must reproduce each reference signature. One fixture carries a raw binary
payload that is not valid UTF-8, one an empty body, and one a body long enough for
a four-digit length prefix. Several fixtures share one key across payload types, so
the cross-type check runs against real material.

One pinned payload type is not ASCII, so its byte length exceeds its character
length and an implementation that counts characters fails it. The attack files
cover multi-byte and astral payload types as well.

The five attack files cover the length prefix under multi-byte and astral payload
types, empty payloads and empty types, a payload that is itself a valid
pre-authentication encoding, base64 malleability in both members, the
duplicate-signature threshold bypass, and the denial of verification through a
wrong key hint.

The name scan decodes JSON strings, base64 in both alphabets, hex and
percent-encoding in every shipped file and compares each token by digest against a
list CI supplies. It runs over the source tree and over the unpacked `.crate`.

## Provenance

The normative rules come from DSSE's own specification text at
secure-systems-lab/dsse commit 851704a2, version 1.0.2 dated 2024-05-10, and not
from a description of it. [PROVENANCE.md](../PROVENANCE.md) ships with the crate and records each source
and the commit it was read at.
