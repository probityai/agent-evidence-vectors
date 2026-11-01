# Credential-release vectors

Cases for `credential-release/v1`: a broker's record of a credential released to an agent
against an [agent-card receipt](../vectors-agent-card-receipt/README.md). The expected
decision and reason for every case are in `MANIFEST.json`, and the predicate is specified
in [spec/predicates/credential-release.md](../spec/predicates/credential-release.md).

[![Checked with Probity](https://img.shields.io/badge/checked-with_Probity-0969da?logo=data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAMAAABEpIrGAAAAkFBMVEX8%2B%2Bzr5NPgyrfKyLnSq5Wzo4tWltqRkZI2kPU1kvk1j%2FMwkPgzjfI2jO80jO40jO3MdWOZc1SLblN1aFxxXFJzVDY2i%2B40i%2B00i%2Bw0i%2Bs0ius1iOZAapwugNYtdbUqaq0qV4tkRzJXOB47Oz43JRkjNEYiHBwlFxIfFxMcEg0XEQ0WEAwXDAUWCAEOCQcJAgCa503RAAAB3klEQVR42rWT2ZacIBCGceHYoN240SK2Crig4vL%2BbxfszJyZTmaSm6S4rI9a%2FwK3vxj41wDj5E9AwS%2Foxjn7DmARqgVHCBHyJcBxJeZtEG2Nv4hAGEPXYVumddvWAbFfgJJECDfDukxa63ldmw%2FiCTCEK%2BteFzNbQI%2BbQPwzwKJGjNO2LMacxNqK1wgcNfO2mqfbHMs8NEkeXT8AjurRTKfbMlqOa5vFyc8cZclu4PSvWptlPlOMeb4PsQu78MoYQWFIwKUet0nPZl%2FMki1H3x%2FKd1PVhhdkS2tDgM7m9bR3XX8EXtYde59SSVVXNx2NMwuIbbGl74HUu%2BcFXrArSpXqlVSpGz8sUG%2FjoCej1RHA6ZAgl1SmUvVUQjduEGDIdt0MxuwjCHYNAZSwT1IbhaZ%2BFt7BrUAXbguxnx3gZ9AJVJLal0hKaYv4OShGbu249Z4F4jhQ1PcpTUYLDBF5WxZB9dBB14O%2Bm6eu48QQpjBXIizf113iS9sF0LYxZMD1PODbVvtznu96sGOrWyFEiwQEwHNcC8gaF58UxfG1qiqMqzx2AACJ0i0qXyRXEIwjwnD1SBOYdKJ%2B7vxF1eRUaxGF9ePRVgiX3xxOccdhiK5v6v%2Fysgp2Z%2BR%2F3ebv9gP5RU8tSdZhDwAAAABJRU5ErkJggg%3D%3D)](https://github.com/probityai/probity)

The record names the receipt by digest, copies the two receipt fields the decision turned
on, names the revocation list it consulted by digest, and states the credential's audience,
scope and lifetime. It has no field that can hold the credential, a hash of it or a
fingerprint of it, so it can be shared without sharing anything that works as a secret.

| Case | Expected |
| --- | --- |
| accept-release-on-passing-receipt | accept, `release_bound` |
| accept-pass-indirect-minimum | accept, `release_bound` |
| accept-ttl-ends-at-receipt-expiry | accept, `release_bound` |
| accept-released-at-receipt-issued-at | accept, `release_bound` |
| statement-not-json | reject, `statement_malformed` |
| statement-type-wrong | reject, `statement_type_wrong` |
| predicate-type-wrong | reject, `predicate_type_wrong` |
| subject-digest-uppercase | reject, `subject_malformed` |
| credential-carries-secret | reject, `credential_fields` |
| credential-carries-token-hash | reject, `credential_fields` |
| predicate-min-result-degraded | reject, `predicate_malformed` |
| predicate-ttl-zero | reject, `predicate_malformed` |
| predicate-ttl-boolean | reject, `predicate_malformed` |
| predicate-scope-unsorted | reject, `predicate_malformed` |
| predicate-scope-empty | reject, `predicate_malformed` |
| predicate-receipt-type-other | reject, `predicate_malformed` |
| predicate-broker-missing | reject, `predicate_malformed` |
| receipt-digest-mismatch | reject, `receipt_digest_mismatch` |
| receipt-malformed | reject, `receipt_malformed` |
| receipt-fields-differ | reject, `receipt_fields_differ` |
| subject-not-receipted | reject, `subject_not_receipted` |
| receipt-not-passing | reject, `receipt_not_passing` |
| receipt-not-current | reject, `receipt_not_current` |
| receipt-not-current-at-valid-until | reject, `receipt_not_current` |
| credential-outlives-receipt | reject, `credential_outlives_receipt` |
| revocation-list-digest-mismatch | reject, `revocation_list_digest_mismatch` |
| revocation-list-malformed | reject, `revocation_list_malformed` |
| revocation-list-other-signer | reject, `revocation_list_signature` |
| revocation-list-stale | reject, `revocation_list_stale` |
| receipt-revoked | reject, `receipt_revoked` |

Each rejected case is built so the check it names is the first that fails and every
earlier check passes. The accepted cases are controls.

## What a case holds

`statement.json` is the unsigned release Statement. `receipt.json` is the receipt
statement it names. `revocations.json` is the revocation list it says it consulted, a DSSE
envelope signed with Ed25519. `context.json` carries `issuerKey`, the base64 public key of
the receipt signer, and `now`, which this suite does not use: every time is judged at the
release's own `releasedAt`. The keys are test keys derived from public labels.

## The checks, in order

A verifier names the first check that fails.

1. The release statement is strict JSON with its four members, the in-toto Statement v1
   type and the credential-release predicate type (`statement_malformed`,
   `statement_type_wrong`, `predicate_type_wrong`).
2. `subject` is one member whose digest holds only a lowercase SHA-256
   (`subject_malformed`).
3. The credential object has no member outside `kind`, `audience` and `scope`
   (`credential_fields`).
4. The predicate has exactly its members, each well formed (`predicate_malformed`).
5. The receipt's bytes hash to the digest the release names
   (`receipt_digest_mismatch`), are a well formed receipt (`receipt_malformed`) and say
   what the release copied (`receipt_fields_differ`).
6. The release's subject is the receipt's subject (`subject_not_receipted`).
7. The receipt's result meets `minResult` (`receipt_not_passing`).
8. The receipt was current at `releasedAt` (`receipt_not_current`).
9. The credential expires no later than the receipt (`credential_outlives_receipt`).
10. The consulted list hashes to the digest the release names
    (`revocation_list_digest_mismatch`), is well formed, signed by the receipt signer and
    current at `releasedAt`, and does not name the receipt
    (`revocation_list_malformed`, `revocation_list_signature`,
    `revocation_list_stale`, `receipt_revoked`).

A release that passes every check is `accept` with reason `release_bound`.

## What a pass establishes

The record is internally bound: the credential went to the card a passing, current receipt
names, it ends no later than that receipt, and the list the broker says it consulted is the
one given and does not revoke the receipt.

## What a pass does not establish

- That the broker actually gated the release, or that its key is the broker's.
- That the credential was used as scoped or was not copied after release.
- That the receipt was a good evaluation; see the receipt corpus.

## Running it

```sh
pip install agent-evidence-vectors
agent-evidence-vectors --corpus vectors-credential-release
```

A verifier under test takes `credential-release/v1 <case-dir> --json`, prints one JSON
object carrying `decision` and `reason`, and exits 0 for `accept` and 1 for `reject`:

```sh
agent-evidence-vectors --corpus vectors-credential-release --verifier './verifier'
python3 vectors-credential-release/check_vectors.py --verifier './verifier'
```

`aee-verify vectors-credential-release` judges the same cases with the Go reader.
Regenerate the cases with `python3 vectors-credential-release/gen_vectors.py`.
