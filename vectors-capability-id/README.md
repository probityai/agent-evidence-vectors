# Capability identifier vectors (draft)

Cases for deriving a `capability_id` from the capability it names, and for
checking that the party invoking the capability copied that identifier rather
than choosing one. They answer the question the Janssen Lock Server TRACE design
leaves open: the design keys its evidence graph on `capability_id` and requires
it to resolve to an action and a resource, and it does not say how the
identifier is generated or by whom.

## The rule these cases test

1. A capability descriptor is a JSON object with an `action` string and a
   `resource` object, and optionally `constraints`.
2. The descriptor is admitted before it is hashed: no duplicate member names, no
   number that is not an integer spelled as one, no integer of magnitude 2^53 or
   more, no lone surrogate in any string, no NaN or Infinity.
3. `capability_id` is `sha256:` followed by the lowercase hex SHA-256 of the
   descriptor's RFC 8785 bytes.
4. The identifier is minted where the policy decision is made and carried in the
   decision record. The gateway that invokes the capability copies it and also
   carries the descriptor of the call it made, so a verifier can recompute both.

## Members

`MANIFEST.json` lists each member with the verdict it expects and why.
`members/<id>.json` holds the decision and invocation records, with each
descriptor kept as raw text so that a duplicate member or an unsafe number
survives to the checker.

| id | expect |
|---|---|
| CAP-A1 | valid |
| CAP-A2 | valid (member order and whitespace differ, identifier does not) |
| CAP-A3 | valid (largest safe integer) |
| CAP-R1 | duplicate-member |
| CAP-R2 | integer-not-ijson-safe |
| CAP-R3 | number-not-integer |
| CAP-R4 | invoker-chosen-id |
| CAP-R5 | id-not-derived |
| CAP-R6 | descriptor-mismatch |
| CAP-R7 | ill-formed-string |

## Running

    python3 vectors-capability-id/gen_vectors.py     # regenerate
    python3 vectors-capability-id/check_vectors.py   # exit 0 when every member is judged as expected

The canonical bytes of every accepted descriptor were compared with the
`rfc8785` Python package and matched.

Status: draft. Not yet wired into the suite's manifest, `aee-verify` or CI.
