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

## Reason codes

A reader that checks a DNS-AID record against a key set it holds under a `kt_inclusion` key authority (profile
`dns-aid-sig-binding/v1`) answers with a decision and the reason codes that led to it. The decision is `agrees` when
nothing failed. A refusal is `contradicted` when the evidence disproves the record, and `cannot-tell` when the evidence
cannot settle it; `cannot-tell` is never `agrees` and is invalid on the rail. The reference reader (`corpora/vectors-dns-aid-sig-v01/check_vectors.py`) answers with the first check that fails. It
reads the JWS (`jws-malformed` to `signature-invalid`), then the payload (`payload-duplicate-member`, `payload-not-object`,
`payload-integer-required`, `expired`, `endpoint-mismatch`), then the `svcb1` digest, then the key authority (`zone-absent` to
`key-set-not-pinned`), and last `iat-in-future` and `svcb-claim-absent`.

| Reason | Decision | Reported when |
| --- | --- | --- |
| `jws-malformed` | contradicted | The compact JWS is not three dot-separated segments, a segment is not base64url text, or the header is not a JSON object. A reader answers this and never crashes on it. |
| `base64url-non-canonical` | contradicted | A segment decodes but is not the canonical base64url of its bytes, because its text sets unused low bits (RFC 4648 section 3.5). |
| `header-duplicate-member` | contradicted | The JOSE header names one member twice, so a first-wins parser and a last-wins parser read different headers. |
| `crit-refused` | contradicted | The header carries `crit` (RFC 7515 section 4.1.11): an empty list, an extension the reader does not understand, or a registered header such as `alg`. The profile defines no extension. |
| `alg-not-es256` | contradicted | `alg` is anything but `ES256`, `none` included. |
| `signature-length` | contradicted | The ES256 signature is not 64 bytes. |
| `signature-invalid` | contradicted | The signature does not verify under any key of the key set. |
| `key-unusable` | cannot-tell | The key set holds no usable EC P-256 key, so nothing can check an ES256 signature. This says nothing against the record. |
| `payload-not-object` | contradicted | The signed payload is not a JSON object: an array, a scalar, or text that is not JSON. |
| `payload-duplicate-member` | contradicted | The payload names one member twice, `fqdn` for example. |
| `payload-integer-required` | contradicted | `port`, `iat` or `exp` is not a JSON integer: `443.0` is not `443`. |
| `iat-in-future` | cannot-tell | `iat` is later than the check time plus 300 seconds of skew, so the record is not yet attested. |
| `expired` | contradicted | `exp` is not later than the check time. |
| `endpoint-mismatch` | contradicted | The signed `fqdn`, `target`, `port` or `alpn` differs from the served record. The served protocol is the record's `proto` when it has one, else its `alpn`. |
| `svcb-claim-absent` | cannot-tell | The payload carries no `svcb1` digest, so the served `cap`, `cap-sha256`, `policy` and `realm` are not attested. |
| `svcb1-digest-mismatch` | contradicted | The served parameters differ from the digest the payload signs: a value that was never signed, an empty value where none was set, a digest without the `svcb1:` prefix, or a signed value that holds a newline. |
| `zone-absent` | cannot-tell | The record names no publishing zone, so no key authority can be looked up for it. |
| `jwks-host-not-zone` | contradicted | The key set was fetched from a host that is neither `dns-aid.<zone>` nor the zone, over https. |
| `key-authority-absent` | cannot-tell | The consumer presents no key authority, so nothing ties the key set to the owner of the zone. |
| `key-authority-kind-unread` | cannot-tell | The key authority is of a kind the reader does not read: it reads a `pin`, and a DNSSEC chain is not one. |
| `key-set-not-pinned` | contradicted | The fingerprint of the supplied key set differs from the fingerprint the consumer pinned for the zone. A key set that travels with a record proves nothing about its owner. |

A record is accepted only when none of these applies, and then the reader names the fingerprint of the keys it trusted.

## Reference reader

agent-evidence-verify (probityai/probity, `packages/agent-evidence-verify`): its `kt-inclusion`
key-authority kind computes the same leaf and audit path, and its `dns_aid_sig/v1` claim type, which
applies [profile `dns-aid-sig-binding/v1`](../profiles/dns-aid-sig-binding/v1.md), requires a key
authority before it agrees. Every verdict states the fingerprint of the keys it trusted in the form
of `key_set_sha256` above.
