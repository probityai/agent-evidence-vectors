# Revocation list

One signed, cumulative revocation list format, and what a verifier must refuse.
A list is `{"body": BODY, "sig": base64(Ed25519 over "probity-revocation-v1\0" || JCS(BODY))}`;
lists are chained by sequence number and digest, and an entry, once published,
stays in every later list byte for byte. A verifier pins its root key ids out of
band and never reads one from a list.

Each case under `cases/` is what one verifier sees: `roots.json` (the pinned root
key ids) and the signed lists it is handed, in order. `MANIFEST.json` states, per
case, the decision, the full refusal (code, or code:detail) and the index of the
refused list, the list in force when the verdict was reached, and the ListDigest
of every list file.

The cases whose `source` is `shared:RLnn` are the shared vectors every reader of
this format answers, pinned at `aee/testdata/revocation-list.json`. The `minted`
cases add one refusal for each check the shared set does not reach alone.

Judge the corpus with the reference verifier:

```sh
go run ./cmd/aee-verify corpora/vectors-revocation-list
```

Rebuild it with `python3 corpora/vectors-revocation-list/gen_vectors.py`; never
edit a case file by hand.
