# Input and result contract

The API envelope carries `record.record_canonical`, `record.signature_ed25519_b64`
and `record.public_key_ed25519_b64`. The local key document has
`public_key_ed25519_b64`. Its byte hash and expected key URL are separate operator
inputs; the reader never adopts the envelope's key as its trust source.
Inputs are regular files no larger than 128 KiB. JSON may have at most 64 nested
containers; quoted brackets do not count. This limit is independent of Python's
parser recursion limit.

The record hash covers the exact UTF-8 bytes of `record_canonical`. The Ed25519
signature covers those same bytes. Verification happens on the supplied bytes,
after comparison with their pin, with no reserialization before verification.
The reader separately checks the documented sorted-key, no-space JSON form.
This finite profile uses ASCII member names and integer numbers, matching the
retained records. It refuses other canonical-value shapes rather than guessing
a cross-language canonicalization rule. This is not a general RFC 8785 implementation.

The signed native `purpose` grammar is `a2a-conduct-walk-v1: ` followed by a literal
URL. The reader compares that URL with the requested target exactly. It also
requires agreement with signed `conduct_ext.target` and node 3's POST request URL.
It does not parse a human reason as a subject or normalize URLs, slashes, Unicode
or percent encodings. The retained full-walk profile has four nodes and eight assertions.

Assertion results must be boolean or null. Null means unevaluated. The reader
recomputes `n_pass`, `n_total` and `ok`; a declared `PASS` cannot hide a false result.
The producer's outcome label is carried separately. A false assertion produces
`REPORTED_ASSERTION_FAILURE`; all-null assertions produce `NO_EVALUATED_ASSERTIONS`.

```sh
.venv/bin/python -m witness_case.reader fixtures/a.api.json fixtures/a.key.json \
  --record-sha256 747ecd97635e104e75185212cfb70e3cc37310ea1f41966a818bfb5b5d57df15 \
  --key-document-sha256 c2aeb7c14095aa8e22eeb6fea2d7d8975ba77db87825a25738155ff77f0bf609 \
  --key-url https://pipavlo82.github.io/keys/witness.json \
  --target https://gate.horizonshield.dev/a2a --operator 'your operator identity'
```

Exit 0 means a matching signed observation with no reported false assertion and
at least one evaluated assertion. Exit 1 preserves a target mismatch, reported
assertion failure or no evaluated assertions. Exit 2 is an input or verification
refusal, with its machine-readable reason. Every completed read emits JSON on stdout.
Argument errors use argparse's stderr output.

The result authenticates a record under the explicitly pinned key. It carries the
witness's declared vantage, walk time and card-verification result. This reader
does not perform a new network walk, recompute response claims, verify the card,
establish historical key or domain control, validate OpenTimestamps, or infer
unaffiliated independence. The operator identity is a caller declaration.
