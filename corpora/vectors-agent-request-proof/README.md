# Agent request-proof vectors

Cases for `agent-request-proof/v1`, predicate type
`https://probityai.github.io/agent-evidence-vectors/predicate/v1/agent-request-proof`.

An agent that signs each HTTP request with a short-lived RS256 proof JWT binds the
request to its key: the proof names the method (`htm`), the path (`htu`), the SHA-256
of the transmitted body (`body_sha256`) and a single-use `jti`. The receiving service
checks the proof and discards it, so nobody can re-check the call afterwards. This
predicate keeps it. The recorder that received the request writes an in-toto Statement
v1 in RFC 8785 bytes and signs it in a DSSE envelope. The subject is the body digest.
The predicate carries the request, the compact proof, the principal's RSA public JWK
with its registered RFC 7638 thumbprint, and the time the request was observed. A third
party re-runs every check the service ran, offline, after the call.

The principal is verified, not reported: the record carries the key the proof verifies
under and the thumbprint it was registered by, so a reader recomputes the binding
instead of trusting an authentication method the recorder wrote down.

The proof profile is the per-request agent proof of the Okta AI Agent v2 contract as
[openbox-ai/openbox-sdk-python](https://github.com/openbox-ai/openbox-sdk-python/blob/e319c9311070931579a14a07e95251b4adf209b8/openbox_core/identity_okta.py)
signs it at commit `e319c9311070931579a14a07e95251b4adf209b8` (header `typ`
`openbox-agent-proof+jwt`). The `upstream-golden` case records that repository's own
golden fixture `tests/signing/identity_v2/evaluate.json` verbatim, under its published
fixture key, and it verifies here.

The column headed "proof verifies" is the point of the corpus: most rejected records
carry a proof whose RS256 signature verifies under the key the record names, and only
the binding refuses them.

| Case | Proof verifies | Expected |
| --- | --- | --- |
| request-bound | yes | verified, `request_bound` |
| upstream-golden | yes | verified, `request_bound` |
| distinct-jti-sequence | yes | verified, `request_bound` |
| request-bound-pinned | yes | verified, `request_bound` |
| upstream-golden-pinned | yes | verified, `request_bound` |
| statement-malformed | no | rejected, `statement_malformed` |
| recorder-signature-invalid | yes | rejected, `recorder_signature_invalid` |
| wrong-typ | yes | rejected, `typ_mismatch` |
| alg-none | no | rejected, `alg_not_allowed` |
| embedded-jwk | yes | rejected, `alg_not_allowed` |
| thumbprint-mismatch | yes | rejected, `thumbprint_mismatch` |
| proof-signature-invalid | no | rejected, `proof_signature_invalid` |
| principal-mismatch | yes | rejected, `principal_mismatch` |
| audience-mismatch | yes | rejected, `audience_mismatch` |
| kid-mismatch | yes | rejected, `kid_mismatch` |
| tenant-mismatch | yes | rejected, `tenant_mismatch` |
| tenant-claim-absent | yes | rejected, `tenant_mismatch` |
| htm-htu-mismatch | yes | rejected, `htm_htu_mismatch` |
| body-digest-mismatch | yes | rejected, `body_digest_mismatch` |
| expired | yes | rejected, `proof_expired` |
| excessive-lifetime | yes | rejected, `proof_expired` |
| replayed-jti | yes | rejected, `replayed_jti` |

## What a case holds

- `case.json`: the recorder's Ed25519 public key (`recorderKey`, base64) and the
  envelopes in the order the recorder wrote them.
  A pinned case adds `pins` (`audience`, `kid`, `claims`), the verifier's policy.
- `envelope-N.json`: a DSSE envelope, payload type `application/vnd.in-toto+json`,
  signed by the recorder. Every envelope but the last is an earlier record that
  verifies; the decision is the last one's.

## The checks, in order

A verifier names the first check that fails. The order is part of the contract.

1. The payload is an in-toto Statement v1 of this predicate type with one sha256
   subject and every predicate member (`statement_malformed`).
2. The DSSE signature verifies under the recorder key (`recorder_signature_invalid`).
3. The proof header's `typ` is the profile's (`typ_mismatch`).
4. The header's `alg` is `RS256` and it embeds no `jwk`, `jku`, `x5u` or `x5c`
   (`alg_not_allowed`).
5. The RFC 7638 thumbprint of the principal JWK is the registered thumbprint
   (`thumbprint_mismatch`).
6. The RS256 signature verifies under that JWK, whose modulus is at least 2048 bits
   (`proof_signature_invalid`).
7. The proof's `iss` and `sub` are the principal's issuer and subject
   (`principal_mismatch`).
8. The proof's `aud` is the audience the verifier pins (`audience_mismatch`).
9. The header's `kid` is the key identifier the verifier pins (`kid_mismatch`).
10. Every tenant claim the verifier pins (for the upstream profile, the `obx_`
    organisation and deployment claims) is present in the proof and equal
    (`tenant_mismatch`).
11. `htm` and `htu` are the recorded method and path
    (`htm_htu_mismatch`).
12. `body_sha256` and the statement subject are the SHA-256 of the recorded body
    (`body_digest_mismatch`).
13. `iat` <= `observedAt` < `exp`, and `exp - iat` is within the profile's lifetime
    (`proof_expired`).
14. No earlier record from the recorder carries the same issuer and `jti`
    (`replayed_jti`).

Checks 8 to 10 read the relying party's pins from the case's `case.json`
(`pins`: `audience`, `kid`, `claims`). The pins are policy of the party that
verifies, not part of the record, so a profile that pins `aud`, `kid` and the
tenant claims adds checks without a format change. A pin a case does not name
switches its check off. The pinned rejections carry a proof whose signature
verifies and whose binding to the request is sound; with the pins removed they
verify, which the corpus tests prove. `upstream-golden-pinned` pins the upstream
fixture to its own `aud`, `kid` and `obx_` claims.

A record that passes every check is `verified` with reason `request_bound`.

## Running it

```sh
pip install agent-evidence-vectors
agent-evidence-vectors --corpus vectors-agent-request-proof
agent-evidence-vectors --corpus vectors-agent-request-proof --verifier './verifier'
```

A verifier under test takes `case.json --json`, prints one JSON object carrying
`decision` and `reason`, and exits 0 for `verified` and 1 for `rejected`.
`aee-verify vectors-agent-request-proof` judges the same cases with the Go reader. Regenerate with
`python3 corpora/vectors-agent-request-proof/gen_vectors.py`. Every key is derived from a published label in
the generator, so anyone can rebuild every signature; the keys protect nothing.

Passing these cases does not establish that `observedAt` is true, which needs a
timestamp the recorder does not control.
