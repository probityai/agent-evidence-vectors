# Proposed text for draft-gilda-audit-agent-audit-record-04: the rules seven reject members test

`X1` to `X18` of `vectors-agent-audit-record` each change one field of an
existing member. Eleven of them test a rule -03 states. The seven below test a
rule only this text states, so the corpus marks them `proposed` until a
published revision carries it. A verifier written from -03 is not scored on
them.

## Section 4.1.1, JSON profile (`X1`)

Add:

> Every number in a Statement MUST be an integer, and MUST be written as one: an
> optional minus sign followed by digits, with no fraction part and no exponent.
> A number written with a fraction part or an exponent makes the Statement
> malformed whatever its value, so `0.5`, `1.0` and `1e2` are each refused
> (vector `X1`). A verifier MUST NOT round, truncate or convert such a number.
> RFC 8785 writes `1.0` as `1` and `1e2` as `100`, so a verifier that accepted
> those tokens would derive one set of canonical bytes from two documents.

## Section 4.8 (new), the Statement and predicate types (`X4`, `X5`)

> `_type` MUST be the string `https://in-toto.io/Statement/v1`, compared byte
> for byte (vector `X4`). `predicateType` MUST equal the predicate type URI the
> verifier was configured to accept, compared byte for byte, the expected URI
> taken from the verifier's configuration and never from the record (vector
> `X5`). A Statement failing either is malformed.

## Section 4.9 (new), sets of records (`X17`, `X18`)

> A set is one JSON text, read under the JSON profile, whose value is an object
> with one defined member, `records`, an array of DSSE envelopes written as JSON
> objects. A set that is not JSON, breaks the JSON profile, is not an object, has
> no `records` member, or whose `records` is not an array is malformed, and no
> check runs on any record in it (vector `X17`). A verifier judges each record on
> its own; when any record is not valid the set is malformed and the checks
> across records are not run (vector `X18`).

## Section 5.9, consumption (`X6`, `X7`)

Replace "each carrying that permit's `operationKey`, `requestDigest` and
`amount`" with:

> each carrying exactly these members and no other: that permit's
> `operationKey`, `requestDigest` and `amount` (vector `X6`)

-03 says "and no other" of `consumption` only, so a held entry with a fourth
member is left undecided by -03; this closes it. Where the consumption-ledger and
payee proposals add members to a held entry, the list above takes them and keeps
"and no other".

Add after the sentence requiring `decision.operationKey`:

> Wherever `decision.operationKey` is present it MUST be a string of at least
> one character, and so MUST the `operationKey` of each `held` entry (vector
> `X7`). An empty key would be one key every caller without a key shares, so two
> intended operations would read as a retry of each other.
