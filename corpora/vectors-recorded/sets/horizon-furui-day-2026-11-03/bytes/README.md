# FURUI day record of 2026-11-03: the two leaf envelopes and the runner keys

The two leaves of the HORIZON SHIELD FURUI daily Merkle tree for 2026-11-03 (`n` 2, root `e5f2c113…c313`), exactly as the
runner served them at `/furui/day/2026-11-03/leaf/0` and `/leaf/1` on 2026-11-10, the last day it kept them, and the key
file published at `/.well-known/furui-check-keys.json`. Leaf 0 belongs to the day record whose canonical hash is `280f70f3…9f3f`
(`day_record.ledger_canonical_sha256`), ledger batch entry 250.

What the bytes let you recompute, with nothing but SHA-256:

1. `leaf_sha256` is `sha256(0x00 || compact JSON of "envelope" with keys sorted)`, for both leaves.
2. `root` is `sha256(0x01 || leaf-0 hash || leaf-1 hash)`, and each leaf's `proof` holds the other leaf's hash (an RFC 6962 audit path).

What this set does not show: the `runner-1` Ed25519 signature inside each envelope is not checked here, the Bitcoin anchor of
entry 250 is not checked, and the path check does not show that the check recorded in leaf 0 was right. The recorded-set
check says only that these files are the bytes listed in `SHA256SUMS`.
