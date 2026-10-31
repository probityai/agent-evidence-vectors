# A standalone Sigstore-source consumer

The [runnable package](../interop/sigstore-js-threshold-2026-10-04/README.md)
checks offline DSSE envelopes with Sigstore JS's actual PAE and signature
functions at `769a53d8713248a8bf49edfc2a5d1955b0dcc24d`. It adds a consumer
policy for distinct Ed25519 keys without changing the publisher's primitives.
The Rust crate and the JavaScript consumer retain separate implementations.

| Input or outcome | Contract |
| --- | --- |
| Original reference bytes | All 11 Go-produced cases in `vectors/cross_lang_signing.json` stay unchanged, including binary, empty and Unicode cases. |
| Signature input | PAE covers the exact decoded payload and its case-sensitive type. The consumer snapshots once and returns those bytes. |
| Threshold | Count distinct actual SPKI key identities. At thresholds above one, duplicate labels or aliases are refused. |
| `keyid` | An unauthenticated hint that orders attempts and never excludes a trusted key. |
| Malformed signatures | Skip malformed encodings and failed checks while keeping a valid signature usable. Refuse when every encoding is malformed. |
| Base64 | Accept canonical padded standard and URL-safe alphabets. Refuse ignored whitespace, missing padding and nonzero discarded bits. |
| Work bound | Refuse more than 1,024 signature entries before cryptography. |
| Report | A fresh CLI result includes verified bytes, selected policy hash, source pin and accepted key identities. A refusal clears an old passing result. |
| Native selection | Sigstore's class selects the first signature. The owned threshold loop supplies each entry to that native class separately. |

`cases.json` contains 17 authored controls with separate identifiers and exact
expected JavaScript and Rust messages. They are a finite integration test, not
a publisher corpus, reliability estimate or model run. The original 16-row
native task comparison and its unstarted prospective study stay separate.

The standalone installer copies only the consumer, its CLI and hash-checked
originals. A fresh installation refuses an existing destination. The installed
consumer needs Node 24 and no npm dependency download. Its tests run the CLI
from outside the source checkout.

The native evidence here establishes signatures under selected public test
keys. Authority selection, task completion, target effects and a publication
decision need their own records. The selected route does not evaluate a
Sigstore bundle, Fulcio chain, Rekor log or timestamp authority. Source
inspection and source execution are recorded separately from package
installation and outside host adoption.

The source files retain The Sigstore Authors' Apache-2.0 notices and unchanged
license. [Source hashes and adaptations](../interop/sigstore-js-threshold-2026-10-04/source-manifest.json)
make that scope inspectable.
