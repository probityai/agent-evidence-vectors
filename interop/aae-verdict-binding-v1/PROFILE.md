# Profile: AAE verdict record bound to an observed-effect record

## The two records

**Verdict record.** The Section 6.2 record of draft-kroehl-agentic-trust-aae-02: exactly `{"core": ..., "core_digest": ...}`, where `core` carries exactly the eight Section 2.5.3 members and `core_digest = "sha256:" + LOWERHEX(SHA-256("aae:enforce-core:v1" || 0x00 || JCS(core)))`. Any other shape is refused (exit 2). The runner never trusts `core_digest`; it recomputes it.

**Evidence record.** An in-toto Statement with `predicateType` `https://probityai.github.io/agent-evidence-vectors/predicate/v1/observed-effect` ([spec](../../spec/predicates/observed-effect.md)) in a DSSE envelope. Validity is decided by this repository's observed-effect reference verifier, `vectors-observed-effect/check_vectors.py`, under the pinned observer key. This adapter reads two members itself: `predicate.authorityDigest` and `predicate.mutation`.

## The binding field: no new member

The observed-effect predicate already has the field this needs. `authorityDigest` is "the [RFC 8785] digest of the authority document under which mutation was permitted: a delegation certificate, a policy bundle, a scoped grant", required unconditionally and inside the observer's prior commitment, so it is fixed before the interval opens.

This profile names the authority document: **the AAE verdict record itself**, the two-member object above. The binding value is therefore

```text
authorityDigest = LOWERHEX(SHA-256(JCS({"core": <core>, "core_digest": <core_digest>})))
```

The AAE core digest sits inside those bytes, so the evidence record commits to the verdict's identifier and to the core it names. A third party holding the pair recomputes both digests from the verdict record alone. The two constructions are never compared with each other: one is AAE's tagged digest of the core, the other is the predicate's untagged digest of the record.

`binding.status` is `MATCH` when the cited value equals that digest (compared with `hmac.compare_digest`), `MISMATCH` when it differs, and `ABSENT` when there is no evidence record.

## Claims kept separate

| Result | Established by | Never inferred from |
|---|---|---|
| authorization | the recomputed core digest; the verdict is what the issuer asserted at issuance | the evidence record |
| binding | the cited digest against the verdict record's digest | the verdict value |
| execution | `CLAIMED_BY_BOUND_RECORD` only for a bound record that verifies and states `mutation: observed`; otherwise `UNKNOWN` | the authorization, however valid |
| completeness | never established | anything |

A DENY verdict bound to an evidence record still reports the DENY: the record then claims a mutation the issuer did not authorize, and the report says both.

## Structural trace conventions

The draft requires structural predicates in the digested trace (Section 2.5.2: "whether a mandate was present, whether the action bound to a grant, and which disposition applied") but does not name them or fix their `field`, `value` and `bound`. The v1.4.0 digests depend on all of it. This kernel uses the convention the vectors encode:

| Predicate | field | value | bound |
|---|---|---|---|
| `mandate_present` | null | null | null |
| `transaction_present` | null | null | null |
| `type_fields` | `"action"` | sorted action member names, or null | the type_fields of the first grant that matched (PASS) or of grant 0 (FAIL) |
| `action_binding` | `"action"` | the action digest | the same digest on PASS, null on FAIL |
| `disposition` | null | the disposition | null |
| `exact`, `enum`, `range` | the constraint path | the transaction value, or null when absent or when the constraint itself is malformed | the constraint value, values array (or its length past 512 members), or `{"lo", "hi"}` |
| unknown type | the constraint `field` | null | null |
| `prior_ratifiable` | null | the prior verdict | null |
| `authority_proof` | null | null | null |
| `mandate_binding` | `"mandate"` | the supplied mandate's digest | the prior record's mandate_digest |
| `authority_in_mandate` | `"authority"` | the claimed DID | every DID the mandate names, in order |
| `authority_signature` | `"signature"` | null | null |

A forbid verdict carries the index of the first matched forbidding grant as `grant_index`.

The 26 core digests reproduced only after this convention was read from MolTrust's `examples/enforce-verify.py`. Two implementations written from the draft text alone would agree on every verdict and not on the digests, and Section 2.5.3 makes byte-identical digests the conformance condition. The convention belongs in the draft or in the vectors, which today state only `predicate` and `result` for structural entries.

## Where the vectors and the draft disagree

Section 2.2 says the MANDATE block "MUST contain an actions array", and Section 2.2.1 says `actions` "remains REQUIRED" and that a grant naming an action the mandate does not list makes the mandate malformed. None of the 26 v1.4.0 mandates carries `actions`. Read literally, vectors 01, 11, 13 and 15 (PERMIT) and 19 (PENDING) would be DENY, and Section 10's statement that every 2.2.1 requirement has a vector does not hold for this one. This kernel follows the vectors, and `test_no_vector_mandate_carries_actions` records the observation on every run so that a vector set adding `actions` turns it red.

MolTrust's reference example compares digests and values with `==` (`examples/enforce-verify.py` lines 129, 275 and 403), where the draft asks for constant-time comparison. No vector can observe the difference.

## Where no vector reaches and the draft is silent, this kernel fails closed

- A constraint whose `type` is not a string is labelled `unknown`, never a host-language spelling of the value.
- A claimed authority that is a DID URL (contains `/`, `?` or `#`) or a DID named twice across the principal and `ratification_authorities` matches no authority (Section 6.4).
- Keys and signatures must be exactly 64 and 128 hexadecimal digits; whitespace is a failed decode.
- A non-array `ratification_authorities` contributes no authority.
- A prior record without a well-formed `mandate_digest` is a caller error.

Strings, actions and digests are compared with `hmac.compare_digest`, and every enum member is compared. Python offers no stronger constant-time guarantee than that.

## Input profile

Every JSON input is at most 64 KiB of strict UTF-8 without a byte-order mark, an object at the root, unique member names at every depth, no floating-point or non-finite numbers, integers within 2^53 - 1, depth at most 32 and at most 8192 nodes. Outside it the run exits 2. The kernel functions themselves accept any parsed JSON, so a float in a range position is a failed predicate when the kernel is called directly.
