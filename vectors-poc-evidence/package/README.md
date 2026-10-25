# poc-evidence-vectors

Conformance vectors and an independent twin verifier for the evidence artifacts of the Proof-of-Control standard (LFDT-ProofOfControl, v1.0 draft).

For implementers of a Proof-of-Control verifier or evidence producer, and for the working group that wants a requirement to name a test.

```
pip install poc-evidence-vectors==0.1.0
python -m poc_evidence_vectors.run_vectors
```

```
poc-evidence-vectors 0.1.0: 171 passed, 0 failed, corpus_sha256=6e22b2503f1767125800d6bb9e1f96bd21c99dcfaffbd0f83362a739e8898111
```

To test your own verifier, pass `--verifier "your-command"`. It receives one case as JSON on stdin and prints `{"result": "accept"}` or `{"result": "reject", "code": "..."}`. A rejection counts only when its code is one of the reasons the case names, because rejecting for the wrong reason is not a pass. The runner is standard library only.

Conformant means passing this corpus at a pinned version. The `corpus_sha256` on the last line is what to pin beside the version number.

## What is in it

171 cases, built from the specification at commit `93d0e282fc177d5df741de4cdd6a0d0dacf1955a`. Each case names the requirement ids it tests, and each negative case differs from an accepted base by one mutation.

| Kind | Cases | What it tests |
| --- | --- | --- |
| token | 87 | claim-set structure, tagged digests, canonical form, duplicate keys, signatures, MODIFY binding |
| inclusion | 37 | RFC 6962 inclusion proofs at nine tree sizes, and the ways a proof can lie |
| consistency | 23 | append-only proofs, forked and reordered histories |
| chain | 15 | hash-chain replay: alteration, deletion, reordering, truncation, a re-signed rewrite caught by an anchor |
| canonical | 9 | RFC 8785 digests for strings, key order, numbers |

The case classes are `positive`, `negative`, `adversarial`, `robustness`, `finding`, `platform-fact`, `interop`, `ambiguity` and `observation`. The last four are places where the specification text is silent or the reference code differs from it, and each says so in its `note`.

## The twin

`poc_evidence_vectors/twin.py` shares no code with the specification's reference implementation. Its Merkle checks use the recursive definition in RFC 6962, its canonical form is written from RFC 8785, and its Ed25519 verification is RFC 8032 in plain integers. A case is only trusted when the twin and the corpus agree.

## Status

Version 0.1.0, published on PyPI as `poc-evidence-vectors`. This directory is its source: `package/` is what the wheel ships, `build/` holds the builder (needs the `cryptography` library) and the reference-validator comparison, and `tests/` holds the checks that tie each case to the specification text. Run `python3 vectors-poc-evidence/build/proof-of-control-build.py --check` to confirm the committed corpus is what the builder writes.

| Doc | Where |
| --- | --- |
| Case schema | each file under `corpus/<kind>/` |
| Pinned manifest | `CORPUS-MANIFEST.json` |
