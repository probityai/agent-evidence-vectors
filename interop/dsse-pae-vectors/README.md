# DSSE pre-authentication encoding

`cases.json` pins the DSSE v1 PAE bytes for eight inputs, including payloadTypes whose
character length differs from their byte length and an empty payloadType. The length field
is the decimal count of UTF-8 bytes. An implementation that counts characters prints a
different prefix for every non-ASCII type, and its signatures then fail to verify
elsewhere.

To check a candidate, compute `PAE(payloadType, payload)` for each member; it must equal
`paeHex`. Regenerate with `python3 scripts/gen-dsse-pae-vectors.py`; `--check` fails on
drift.

The PAE is defined for an empty payloadType. Some signers refuse one; the corpus does not
score signing.
