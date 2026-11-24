# Predicate type `predicate/v1/key-set-inclusion`

Type URI: `https://probityai.github.io/agent-evidence-vectors/predicate/v1/key-set-inclusion`

A statement of this type says that every key of one key set was logged, bound to one subject, in a
transparency log whose tree head the consumer pins. It is the evidence a `kt_inclusion` key authority
reads. A signature that verifies under a key proves only that someone held the key; inclusion of that
key, bound to the subject, in a log the consumer trusts is what entitles the key to speak for the
subject. A DNS-AID publisher logs the key set it serves at `https://dns-aid.<zone>/` this way, so a
verifier holding the record, its signature and the JWKS offline can decide whether the key is the
zone owner's.

## Envelope

An in-toto Statement v1 in a DSSE envelope. The statement has one subject: `name` is the subject the
keys speak for (for DNS-AID, the zone in lowercase with no trailing dot) and `digest.sha256` is the
key-set fingerprint defined below.

## Predicate body

| Member | Type | Meaning |
|---|---|---|
| `subject` | string | The subject the keys are bound to; equal to the statement subject's `name`. |
| `keys` | array of strings | The SHA-256 of each key's raw bytes (the Ed25519 public key, or the uncompressed EC point `0x04 || x || y`), lowercase hex, sorted, distinct, at least one. |
| `key_set_sha256` | string | The SHA-256 of the concatenation of `<digest>\n` for each member of `keys`, lowercase hex. Equal to the statement subject's digest. |
| `log` | object | `origin` (the log's checkpoint origin string), `tree_size` (a JSON integer, at least 1) and `root_sha256` (lowercase hex). |
| `inclusions` | array of objects | One per key, in the order of `keys`: `key_sha256`, `index` (a JSON integer) and `path` (an array of lowercase hex SHA-256 hashes), an RFC 6962 audit path. |

Every member is required and no other member is allowed, at any level.

## Verification

1. Parse the statement as I-JSON (RFC 7493). A repeated member name, an integer outside
   plus or minus 2^53 - 1, or a `tree_size` or `index` that is not a JSON integer (`true`, `2.0`)
   refuses it.
2. Check that `keys` is sorted and distinct, that `key_set_sha256` is its fingerprint, and that the
   statement's one subject names `subject` with that digest.
3. For each key, the leaf is the RFC 8785 canonical form of
   `{"key_sha256": "<hex>", "subject": "<subject>"}`. Its RFC 6962 leaf hash, with `path`, at
   `index` in a tree of `tree_size` leaves, must reach `root_sha256`.
4. Accept the log only when `tree_size` and `root_sha256` equal a tree head the consumer pins, or a
   checkpoint for `origin` signed by a key the consumer pins. A statement that carries its own tree
   head and nothing the consumer pins proves nothing.
5. Inclusion shows that the binding was logged. It does not show that no later entry revoked it.

A statement whose key set differs from the JWKS a record was verified under does not vouch for that
record. The type URI is part of the signed bytes: a statement under another type is not this
statement, so renaming the type fails verification.

## Reference reader

agent-evidence-verify (probityai/probity, `packages/agent-evidence-verify`): its `kt-inclusion`
key-authority kind computes the same leaf and audit path, and its `dns_aid_sig/v1` claim type, which
applies [profile `dns-aid-sig-binding/v1`](../profiles/dns-aid-sig-binding/v1.md), requires a key
authority before it agrees. Every verdict states the fingerprint of the keys it trusted in the form
of `key_set_sha256` above.
