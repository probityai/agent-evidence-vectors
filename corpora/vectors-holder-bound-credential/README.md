# Holder-bound credential vectors

Cases for `holder-bound-credential/v1`: does the presenter of a credential hold the key the
credential confirms? A bearer credential works for whoever copies it. A holder-bound one
names a key (`cnf.jkt`, RFC 7800 and RFC 9449 section 6.1), and each use carries a fresh
DPoP proof (RFC 9449 section 4.2) signed by that key. A verifier that passes these cases
refuses a credential that confirms no key, a proof signed by another key, and every way a
proof can be stale, replayed, aimed at another request or made unsigned.

For anyone who issues sender-constrained tokens, anyone who writes the resource-server check
that reads them, and anyone who needs to say whether an agent's credential could have been
used by someone else.

```sh
pip install agent-evidence-vectors
agent-evidence-vectors --corpus vectors-holder-bound-credential
python3 corpora/vectors-holder-bound-credential/check_vectors.py --verifier './verifier'
```

## The record

A record is one `credential` (its `issuer`, validity window `iat` and `exp`, opaque `token`
and, when holder-bound, `cnf.jkt`) and a list of `presentations`. A presentation is the time
`at` the relying party saw a request, the `request` (`htm` method and `htu` target URI
without query or fragment) and the `proof`, a DPoP proof JWT in flattened JWS JSON form (RFC 7515 section 7.2.2: `protected`, `payload`, `signature`). The credential's own signature is
out of scope: whether its claims are genuine is the question of the issuer-signed-marker
test of `identity-assurance-levels/v1`, asked about the same subject. This contract tests
possession only, and no key is chosen by the data it judges: the verifying key is the one the
credential confirms, and a proof whose header key hashes to anything else is refused before
its signature counts.

## What the cases force

The reader applies twenty-one checks in order and names the first that fails. Each refusal is a
passing record with one edit:

| Reason | The edit |
| --- | --- |
| `contract_id_missing`, `contract_id_unknown` | no contract, another contract |
| `record_malformed` | a credential with no presentation |
| `credential_not_holder_bound` | no `cnf`: a bearer credential |
| `credential_not_yet_valid`, `credential_expired` | a request before `iat`, at `exp` (the window is half-open) and after |
| `proof_malformed` | not a JWS; a `crit` header the profile does not read |
| `proof_type_wrong` | `typ` is `JWT` |
| `proof_alg_forbidden` | `alg` is `none`, or a MAC |
| `proof_alg_unsupported` | an algorithm this profile does not read |
| `proof_key_invalid` | the header key has a private member, is absent, or is not a prime-order key: the identity point, an order-two point, or an honest key plus a torsion point, each of which a plain Ed25519 check lets a forger sign for |
| `proof_signature_invalid` | one bit flipped; the request target edited after signing |
| `proof_claims_malformed` | no `jti` |
| `proof_method_mismatch`, `proof_uri_mismatch` | a proof for another method or endpoint |
| `proof_stale`, `proof_from_future` | a proof 61 seconds old, one 6 seconds ahead |
| `proof_ath_missing`, `proof_ath_mismatch` | no access token hash, the hash of another token |
| `proof_key_not_bound` | a valid proof signed by a key the credential does not confirm |
| `proof_replayed` | two requests that carry the same `jti` |

Five accepting members are the controls: one request, two requests, a proof exactly 60
seconds old, one 5 seconds ahead, and a request exactly at the credential's start.

Every member is synthetic and every key is derived from a public seed in `gen_vectors.py`.
`python3 gen_vectors.py` regenerates the corpus byte for byte.

## Status

Version 1. The counts are in `MANIFEST.json`.
