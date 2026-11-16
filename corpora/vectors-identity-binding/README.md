# Agent DID identity-binding vectors

Cases for `agent-did-identity-binding/v1`: a DSSE-signed agent record whose
subject is a `did:web` or `did:wba` DID, the DID documents a resolver would
return for it, and the decision a verifier must reach. The expected decision and
reason for every case are in `MANIFEST.json`.

[![Checked with Probity](https://img.shields.io/badge/checked-with_Probity-blue?style=flat-square&logo=data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAMAAABEpIrGAAAAkFBMVEX8%2B%2Bzr5NPgyrfKyLnSq5Wzo4tWltqRkZI2kPU1kvk1j%2FMwkPgzjfI2jO80jO40jO3MdWOZc1SLblN1aFxxXFJzVDY2i%2B40i%2B00i%2Bw0i%2Bs0ius1iOZAapwugNYtdbUqaq0qV4tkRzJXOB47Oz43JRkjNEYiHBwlFxIfFxMcEg0XEQ0WEAwXDAUWCAEOCQcJAgCa503RAAAB3klEQVR42rWT2ZacIBCGceHYoN240SK2Crig4vL%2BbxfszJyZTmaSm6S4rI9a%2FwK3vxj41wDj5E9AwS%2Foxjn7DmARqgVHCBHyJcBxJeZtEG2Nv4hAGEPXYVumddvWAbFfgJJECDfDukxa63ldmw%2FiCTCEK%2BteFzNbQI%2BbQPwzwKJGjNO2LMacxNqK1wgcNfO2mqfbHMs8NEkeXT8AjurRTKfbMlqOa5vFyc8cZclu4PSvWptlPlOMeb4PsQu78MoYQWFIwKUet0nPZl%2FMki1H3x%2FKd1PVhhdkS2tDgM7m9bR3XX8EXtYde59SSVVXNx2NMwuIbbGl74HUu%2BcFXrArSpXqlVSpGz8sUG%2FjoCej1RHA6ZAgl1SmUvVUQjduEGDIdt0MxuwjCHYNAZSwT1IbhaZ%2BFt7BrUAXbguxnx3gZ9AJVJLal0hKaYv4OShGbu249Z4F4jhQ1PcpTUYLDBF5WxZB9dBB14O%2Bm6eu48QQpjBXIizf113iS9sF0LYxZMD1PODbVvtznu96sGOrWyFEiwQEwHNcC8gaF58UxfG1qiqMqzx2AACJ0i0qXyRXEIwjwnD1SBOYdKJ%2B7vxF1eRUaxGF9ePRVgiX3xxOccdhiK5v6v%2Fysgp2Z%2BR%2F3ebv9gP5RU8tSdZhDwAAAABJRU5ErkJggg%3D%3D)](https://github.com/probityai/probity)

A signature tells a verifier that some key signed the bytes. It does not tell
it that the key belongs to the DID the record is about. The column headed
"signature verifies" is the point of the corpus: several rejected records carry
a signature that verifies under the key the envelope names, and only the
binding between that key and the subject DID refuses them.

| Case | Method | Signature verifies | Expected |
| --- | --- | --- | --- |
| web-verified | did:web | yes | verified, `subject_bound` |
| wba-verified | did:wba | yes | verified, `subject_bound` |
| web-signed-before-rotation | did:web | yes | verified, `subject_bound` (proven in April, before the June rotation) |
| key-not-in-authentication | did:web | yes | rejected, `key_not_authorized` |
| key-absent-from-document | did:web | no | rejected, `key_not_authorized` |
| did-unresolvable | did:wba | no | rejected, `did_unresolvable` |
| web-key-rotated-out | did:web | yes | rejected, `key_rotated_out` |
| wba-deactivated-before-signing | did:wba | yes | rejected, `key_rotated_out` |
| subject-swap | did:web | yes | rejected, `signer_not_subject` |
| did-malformed | did:wba | no | rejected, `did_malformed` |
| wba-fingerprint-mismatch | did:wba | yes | rejected, `binding_fingerprint_mismatch` |
| payload-altered | did:web | no | rejected, `signature_invalid` |
| web-backdated-after-rotation | did:web | yes | rejected, `key_rotated_out` |
| wba-deactivated-after-signing | did:wba | yes | rejected, `key_rotated_out` |
| web-signing-time-unproven | did:web | yes | rejected, `signing_time_unproven` |
| web-forward-dated | did:web | yes | rejected, `signing_time_unproven` |
| web-history-observed-before-transfer | did:web | yes | rejected, `history_unobserved` |
| web-history-observed-unstated | did:web | yes | rejected, `history_unobserved` |
| web-history-observed-at-proof | did:web | yes | verified, `subject_bound` |

`signedAt` is the signer's word. The last four cases hold a signature that a
reader judging the key only at `signedAt` accepts: a record that says it was
signed in March, before the June rotation or deactivation, but that the
verifier can first prove existed in July cannot be told apart from one its
holder backdated after losing the key.

## What a case holds

- `envelope.json`: a DSSE envelope with payload type
  `application/vnd.agent-evidence.agent-record+json`. The payload is the
  RFC 8785 form of `{"signedAt", "statement", "subject": {"id"}}`; the
  signature's `keyid` is a DID URL naming the signing key.
- `did-*.json`: one resolution fixture per DID, `{"did", "observedAt",
  "versions": [...]}`, each version a `didDocument` and its
  `didDocumentMetadata.updated`. The version in effect at `signedAt` is the
  latest one updated at or before it. `observedAt` is the last time the
  resolver read the DID's current document: the history is evidence only up
  to then. A did:web DID is only as stable as its domain, and a domain that
  passes to another registrant publishes no new version, so a record signed
  after that by the former holder's key is invisible in a history observed
  before it. A resolver that reads no document at all (the domain now serves none)
  records that as a deactivated version at the time it read.
- `case.json`: maps each DID to its fixture (a DID with no entry does not
  resolve), and states `provenAt`: the earliest time the verifier itself can
  prove the record existed, from a transparency-log inclusion or a timestamp
  it checked, or else its own clock when it decides.

The did:wba documents follow the did:wba method specification of the Agent
Network Protocol,
[`03-did-wba-method-design-specification.md`](https://github.com/agent-network-protocol/AgentNetworkProtocol/blob/c6a467b4e690137d237d8068f2c60b48955dbaf6/03-did-wba-method-design-specification.md)
at commit `c6a467b4e690137d237d8068f2c60b48955dbaf6`: the binding key is an
Ed25519 `Multikey` under `authentication` and `assertionMethod`, a path DID
ends in `e1_` followed by the RFC 7638 thumbprint of that key (Section 2.2.2),
and a DID superseded by a key change keeps its document with `deactivated` and
`successorDid` (Section 2.5). The did:web documents carry `JsonWebKey`
methods, so a verifier must read both key forms.

## The checks, in order

A verifier names the first check that fails. The order is part of the
contract, so a record that fails two checks has one expected reason.

1. The subject DID and the signer DID are well formed did:web or did:wba
   strings; a did:wba path DID must end in its `e1_` segment
   (`did_malformed`).
2. The DID the signing key belongs to is the record's subject
   (`signer_not_subject`).
3. A resolution fixture exists for that DID (`did_unresolvable`).
4. The case states `provenAt`, and `signedAt` is not later than it
   (`signing_time_unproven`).
5. The fixture states `observedAt`, and it is not earlier than `provenAt`
   (`history_unobserved`).
6. For a did:wba path DID, the `e1_` segment is the thumbprint of an Ed25519
   `Multikey` the document authorises for authentication
   (`binding_fingerprint_mismatch`).
7. Every version in effect from signing through `provenAt` still authorises
   the key and is not deactivated, where a version at or before signing
   authorised it (`key_rotated_out`).
8. The version in effect at signing lists the key under `authentication` or
   `assertionMethod` (`key_not_authorized`).
9. The DSSE signature verifies under that key (`signature_invalid`).

A record that passes all nine is `verified` with reason `subject_bound`.

## Running it

The package judges the corpus with its own reader:

```sh
pip install agent-evidence-vectors
agent-evidence-vectors --corpus vectors-identity-binding
```

A verifier under test takes `case.json --json`, prints one JSON object carrying
`decision` and `reason`, and exits 0 for `verified` and 1 for `rejected`:

```sh
agent-evidence-vectors --corpus vectors-identity-binding --verifier './verifier'
python3 vectors-identity-binding/check_vectors.py --verifier './verifier'
```

`aee-verify vectors-identity-binding` judges the same cases with the Go reader.
Regenerate the cases with `python3 vectors-identity-binding/gen_vectors.py`.
The keys are Ed25519 seeds derived from published labels in the generator, so
anyone can rebuild every signature; they protect nothing.

Passing these cases does not establish that the verifier's `provenAt` is
itself true (that is the timestamp or log the verifier trusts), or that a
resolver fetched the document it returned from the host the DID names.
