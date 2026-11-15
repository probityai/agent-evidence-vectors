# Pre-action verdict vectors

Cases for `preaction-verdict/v1`: may a relying party credit a signed verdict as an independent verdict on this action, issued before the action ran? The record is a Nostr event (NIP-01, kind 30078) signed with BIP-340, and its `content` is a JSON object. Each case is one `case.json`: the record, the keys the relying party trusts, the hash and execution time of the action, and, when the relying party holds Bitcoin block headers, those headers and the anchor that goes with the record.

The record shape, the first eight checks and the key-binding case come from the reader contract babyblueviper1 published in preaction-governance-conformance (`vectors/preaction-verdict` at `641c068`). This corpus rebuilds the cases from its own test keys, so a verifier can run them with no network, and adds the checks that decide whether the verdict existed before the action. `MANIFEST.json` credits the source under `credits`.

Each denied case departs from a conformant case in one place and is credited by a verifier that skips the check it names. The key-binding case is signed by a second key the relying party trusts while its content names the issuer: a verifier that checks the signature and the key set credits it.

## The checks, in the order a verifier applies them

The verifier names the first check that fails.

| Check | Reason on failure |
| --- | --- |
| `case.json` carries `contractId` | `contract_id_missing` |
| `contractId` is the pre-action verdict contract | `contract_id_unknown` |
| the case has the fields and types the contract names | `malformed_case` |
| `id` is the SHA-256 of the NIP-01 array `[0, pubkey, created_at, kind, tags, content]`, compact, non-ASCII unescaped | `event_id` |
| `sig` is a valid BIP-340 signature over `id` under `pubkey` | `signature` |
| `pubkey` is in the relying party's key set | `key_not_in_set` |
| the tags carry `["schema", "invinoveritas.verdict_proof.v1"]` | `schema` |
| `content.verifier_pubkey` equals `pubkey` | `key_binding` |
| `content.decision_ref` is `sha256:` plus the SHA-256 of the RFC 8785 serialisation of the named preimage fields, an absent field set to null | `decision_ref` |
| the action hash equals `content.artifact_hash` | `action_unbound` |
| beacon time is not after `created_at`, and `created_at` is before the execution time | `not_pre_action` |
| when the relying party states a maximum age, the verdict is not older | `stale_verdict` |
| headers held: the beacon names a held header with the beacon's time | `beacon_untrusted` |
| headers held: the record comes with an anchor | `anchor_missing` |
| headers held: folding `commitment` through `path` with SHA-256 reaches the header's merkle root field, and `commitment` is the record id | `anchor_commitment` |
| headers held: the anchor's header is one of them | `anchor_header_untrusted` |
| headers held: the anchor header's time is before the execution time | `anchor_after_action` |

A case that passes every check is `allow`. Its reason is `verified_issuer_clock` when the relying party holds no headers and `verified_anchored` when it does. The first credits the issuer's own word about when it signed: the beacon is a number inside the signed bytes, nothing offline shows it is a real block, and the execution time is whatever the relying party supplies. Only `verified_anchored` shows the verdict existed before the action by a time the issuer does not control. No check judges whether the verdict was right.

The anchor here is a SHA-256 fold to a header's merkle root field, the shape a stamp takes once its path is resolved. It is a simplified stand-in for a full OpenTimestamps proof, which the `vectors-recorded` corpus judges from block headers.

## Running

```sh
pip install agent-evidence-vectors
agent-evidence-vectors --corpus vectors-preaction-verdict
```

To judge your own verifier, run it as `<verifier> <case-dir>/case.json --json`. It prints one JSON object carrying `decision` and `reason`, and exits 0 for `allow` and 1 for `deny`. Pass it to the corpus with `--verifier`.

## Controls

Every denied case departs from a conformant case in one place, and each check is forced by at least one case: switching it off changes a verdict. A verifier that denies everything fails the allowed cases, and one that allows everything fails the denied ones. A fixture whose bytes differ from the manifest is refused before execution. `tests/test_corpus.py` holds each of these as a test, checks the signature arithmetic against the official BIP-340 vectors, and regenerates the corpus byte for byte from `gen_vectors.py`.
