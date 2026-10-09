# Agent DID identity-binding vectors

Cases for `agent-did-identity-binding/v1`: a DSSE-signed agent record whose
subject is a `did:web` or `did:wba` DID, the DID documents a resolver would
return for it, and the decision a verifier must reach. The expected decision and
reason for every case are in `MANIFEST.json`.

A signature tells a verifier that some key signed the bytes. It does not tell
it that the key belongs to the DID the record is about. The column headed
"signature verifies" is the point of the corpus: several rejected records carry
a signature that verifies under the key the envelope names, and only the
binding between that key and the subject DID refuses them.

| Case | Method | Signature verifies | Expected |
| --- | --- | --- | --- |
| web-verified | did:web | yes | verified, `subject_bound` |
| wba-verified | did:wba | yes | verified, `subject_bound` |
| web-signed-before-rotation | did:web | yes | verified, `subject_bound` |
| key-not-in-authentication | did:web | yes | rejected, `key_not_authorized` |
| key-absent-from-document | did:web | no | rejected, `key_not_authorized` |
| did-unresolvable | did:wba | no | rejected, `did_unresolvable` |
| web-key-rotated-out | did:web | yes | rejected, `key_rotated_out` |
| wba-deactivated-before-signing | did:wba | yes | rejected, `key_rotated_out` |
| subject-swap | did:web | yes | rejected, `signer_not_subject` |
| did-malformed | did:wba | no | rejected, `did_malformed` |
| wba-fingerprint-mismatch | did:wba | yes | rejected, `binding_fingerprint_mismatch` |
| payload-altered | did:web | no | rejected, `signature_invalid` |

## What a case holds

- `envelope.json`: a DSSE envelope with payload type
  `application/vnd.agent-evidence.agent-record+json`. The payload is the
  RFC 8785 form of `{"signedAt", "statement", "subject": {"id"}}`; the
  signature's `keyid` is a DID URL naming the signing key.
- `did-*.json`: one resolution fixture per DID, `{"did", "versions": [...]}`,
  each version a `didDocument` and its `didDocumentMetadata.updated`. The
  version in effect at `signedAt` is the latest one updated at or before it.
- `case.json`: maps each DID to its fixture. A DID with no entry does not
  resolve.

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
4. For a did:wba path DID, the `e1_` segment is the thumbprint of an Ed25519
   `Multikey` the document authorises for authentication
   (`binding_fingerprint_mismatch`).
5. The version in effect at signing still authorises the key and is not
   deactivated, where an earlier version authorised it (`key_rotated_out`).
6. That version lists the key under `authentication` or `assertionMethod`
   (`key_not_authorized`).
7. The DSSE signature verifies under that key (`signature_invalid`).

A record that passes all seven is `verified` with reason `subject_bound`.

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

Passing these cases does not establish that `signedAt` is true, which needs a
timestamp the signer does not control, or that a resolver fetched the document
it returned from the host the DID names.
