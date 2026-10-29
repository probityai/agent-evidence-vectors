# OASF record vectors

Cases for `oasf-record/v1`: is an [OASF](https://github.com/agntcy/oasf) record named by a digest a second implementation can recompute, and is the signature over that digest accepted only from the signer the consumer's policy names? Each case is two files: `record.json`, the record's bytes as the producer wrote them, and `case.json`, the digest the producer claims, the certificate identity whose signature over that digest verified, and the identity the policy names.

A record digest is SHA-256 over the RFC 8785 bytes of the record, and a signer must equal the policy exactly, subject and issuer both. Every denied case here departs from a conformant case in one of those rules.

## The checks, in the order a verifier applies them

The verifier names the first check that fails.

| Check | Reason on failure |
| --- | --- |
| `case.json` carries `contractId` | `contract_id_missing` |
| `contractId` is the OASF record contract | `contract_id_unknown` |
| `case.json` has `recordDigest` (`sha256:` and 64 lowercase hexadecimal digits), `signer` and `policy`, each with a `subject` and an `issuer` | `malformed_case` |
| `record.json` is UTF-8 JSON with no duplicate member and no NaN or Infinity | `record_not_json` |
| every integer in the record lies inside the exact range of a double, as RFC 7493 section 2.2 requires | `number_not_exact` |
| the record carries the fields the OASF record object marks required: `name`, `version`, `schema_version`, `description`, a non-empty `authors` list, an RFC 3339 `created_at` and a non-empty `skills` list of named or numbered skills | `oasf_required_field` |
| `recordDigest` is SHA-256 over the RFC 8785 bytes of the record | `digest_mismatch` |
| the signer's `subject` and `issuer` equal the policy's, character for character | `signer_not_policy` |

A case that passes every check is `allow` with reason `conformant`. The signature's cryptography is outside this corpus: [vectors-receipt-signature](../vectors-receipt-signature/README.md) and [vectors-identity-binding](../vectors-identity-binding/README.md) cover it.

## Running

```sh
pip install agent-evidence-vectors
agent-evidence-vectors --corpus vectors-oasf-record
```

To judge your own record store or verifier, run it as `<verifier> <case-dir>/case.json --json`, reading `record.json` beside it. It prints one JSON object carrying `decision` and `reason`, and exits 0 for `allow` and 1 for `deny`. Pass it to the corpus with `--verifier`. A store that names records by a CID rather than a bare digest compares the CID's SHA-256 multihash with `recordDigest`.

## Controls

Every denied case departs from a conformant case in one place, and each check is forced by at least one case: switching it off changes a verdict. Each `digest-over-*` case has an allowed twin holding the same record with the RFC 8785 digest. A verifier that denies everything fails the allowed cases, and one that allows everything fails the denied ones. A fixture whose bytes differ from the manifest is refused before execution. `tests/test_corpus.py` holds each of these as a test, and regenerates the corpus byte for byte from `gen_vectors.py`.
