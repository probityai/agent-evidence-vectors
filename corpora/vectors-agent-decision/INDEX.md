# Agent decision conformance vectors

Emitted by `gen_vectors.py`. Do not edit: the next build overwrites it.

Predicate: `https://auxidus.dev/attestation/agent-decision/v0.1`, proposed in [in-toto/attestation#554](https://github.com/in-toto/attestation/issues/554).

Corpus digest: `a2674abfcf5b0edfaa8fe0f68be393066d962aee95c24362e00ea45ddbed1efc`

| member | verdict | code | arguments | what it carries | parent |
| --- | --- | --- | --- | --- | --- |
| [`recorded-integer-amount`](statements/v56d4b6480ce48273.json) | valid |  | [`v56d4b6480ce48273`](arguments/v56d4b6480ce48273.json) | a recorded call with an integer amount, the base of the state members |  |
| [`overflow-1e400`](statements/ve0417c625a28533c.json) | malformed | `arguments-number-overflow` | [`ve0417c625a28533c`](arguments/ve0417c625a28533c.json) | amount written 1e400, which no double holds, hashed as the null JSON.stringify writes for Infinity | `recorded-integer-amount` |
| [`duplicate-amount`](statements/va8e8df4271c4ab93.json) | malformed | `arguments-duplicate-member` | [`va8e8df4271c4ab93`](arguments/va8e8df4271c4ab93.json) | amount given twice, hashed over the last value as a last-wins parser keeps it | `recorded-integer-amount` |
| [`arguments-not-an-object`](statements/ve8baaedbb81ba750.json) | malformed | `arguments-not-json` | [`ve8baaedbb81ba750`](arguments/ve8baaedbb81ba750.json) | the disclosed arguments are a JSON array, hashed over its own canonical bytes | `recorded-integer-amount` |
| [`number-1e21`](statements/vaccea9396f8bdb6b.json) | valid |  | [`vaccea9396f8bdb6b`](arguments/vaccea9396f8bdb6b.json) | amount written 1e21, hashed over its RFC 8785 spelling 1e+21 |  |
| [`number-1e21-drift`](statements/v15e3eb6b1879db28.json) | invalid | `args-hash-mismatch` | [`v15e3eb6b1879db28`](arguments/v15e3eb6b1879db28.json) | amount written 1e21, hashed over 1000000000000000000000: an integral double at 1e21 written as plain digits, the formatter defect reported on #554 | `number-1e21` |
| [`number-1e16`](statements/vf15b2cf59647c11e.json) | valid |  | [`vf15b2cf59647c11e`](arguments/vf15b2cf59647c11e.json) | amount written 1e16, hashed over its RFC 8785 spelling 10000000000000000 |  |
| [`number-1e16-drift`](statements/v06a8c6ac559daa15.json) | invalid | `args-hash-mismatch` | [`v06a8c6ac559daa15`](arguments/v06a8c6ac559daa15.json) | amount written 1e16, hashed over 1e+16: Python's repr, which switches to exponent form at 1e16 where ECMA-262 waits for 1e21 | `number-1e16` |
| [`number-1-point-0`](statements/vd24ab9accf98f4d1.json) | valid |  | [`vd24ab9accf98f4d1`](arguments/vd24ab9accf98f4d1.json) | amount written 1.0, hashed over its RFC 8785 spelling 1 |  |
| [`number-1-point-0-drift`](statements/v6f68087a6f2ac0d0.json) | invalid | `args-hash-mismatch` | [`v6f68087a6f2ac0d0`](arguments/v6f68087a6f2ac0d0.json) | amount written 1.0, hashed over 1.0: Python's json.dumps, which keeps the .0 of an integral double | `number-1-point-0` |
| [`number-1e-6`](statements/v415f4c2e87fb8bcf.json) | valid |  | [`v415f4c2e87fb8bcf`](arguments/v415f4c2e87fb8bcf.json) | amount written 1e-6, hashed over its RFC 8785 spelling 0.000001 |  |
| [`number-1e-6-drift`](statements/vb131ab1e6d75fc35.json) | invalid | `args-hash-mismatch` | [`vb131ab1e6d75fc35`](arguments/vb131ab1e6d75fc35.json) | amount written 1e-6, hashed over 1e-06: Python's json.dumps, which switches to exponent form below 1e-4 and pads the exponent | `number-1e-6` |
| [`number-1e-7`](statements/v339183abc44352b6.json) | valid |  | [`v339183abc44352b6`](arguments/v339183abc44352b6.json) | amount written 1e-7, hashed over its RFC 8785 spelling 1e-7 |  |
| [`number-1e-7-drift`](statements/vcd4ff5dd804aa429.json) | invalid | `args-hash-mismatch` | [`vcd4ff5dd804aa429`](arguments/vcd4ff5dd804aa429.json) | amount written 1e-7, hashed over 1e-07: a printf-style exponent, padded to two digits | `number-1e-7` |
| [`number-negative-zero`](statements/vd5e7c5e20ab405df.json) | valid |  | [`vd5e7c5e20ab405df`](arguments/vd5e7c5e20ab405df.json) | amount written -0.0, hashed over its RFC 8785 spelling 0 |  |
| [`number-negative-zero-drift`](statements/va49cc7eba1306281.json) | invalid | `args-hash-mismatch` | [`va49cc7eba1306281`](arguments/va49cc7eba1306281.json) | amount written -0.0, hashed over -0.0: Python's json.dumps, which keeps the sign of negative zero | `number-negative-zero` |
| [`number-1e20`](statements/v4894d0a7d91c3fc7.json) | valid |  | [`v4894d0a7d91c3fc7`](arguments/v4894d0a7d91c3fc7.json) | amount written 1e20: the largest power of ten ECMA-262 still writes in plain digits |  |
| [`number-max-double`](statements/v8a3aa5fbe538fc11.json) | valid |  | [`v8a3aa5fbe538fc11`](arguments/v8a3aa5fbe538fc11.json) | amount written 1.7976931348623157e308: the largest finite double, written in exponent form |  |
| [`number-min-subnormal`](statements/v12af945ff61fba34.json) | valid |  | [`v12af945ff61fba34`](arguments/v12af945ff61fba34.json) | amount written 5e-324: the smallest positive subnormal double |  |
| [`integer-max-safe`](statements/vd71376868c0a727b.json) | valid |  | [`vd71376868c0a727b`](arguments/vd71376868c0a727b.json) | amount is the integer literal 2**53 - 1, the last one RFC 7493 admits |  |
| [`integer-past-boundary-as-double`](statements/veca390969b070fe0.json) | valid |  | [`veca390969b070fe0`](arguments/veca390969b070fe0.json) | amount written 9007199254740993.0: a fraction makes it a double by the writer's spelling, and it canonicalizes to the nearest double, 9007199254740992 |  |
| [`integer-2-53`](statements/vaa3f6d878cefece5.json) | malformed | `arguments-integer-unsafe` | [`vaa3f6d878cefece5`](arguments/vaa3f6d878cefece5.json) | the integer literal 2**53, hashed as the double a rounding library reads it as | `integer-max-safe` |
| [`integer-2-53-plus-1`](statements/vbb1394c46dace5ff.json) | malformed | `arguments-integer-unsafe` | [`vbb1394c46dace5ff`](arguments/vbb1394c46dace5ff.json) | the integer literal 2**53 + 1, which no double holds, hashed as 9007199254740992 | `integer-max-safe` |
| [`integer-1e21-digits`](statements/v7448329eed2ae36f.json) | malformed | `arguments-integer-unsafe` | [`v7448329eed2ae36f`](arguments/v7448329eed2ae36f.json) | the integer literal 10**21, hashed as the double 1e+21 a rounding library writes | `integer-max-safe` |
| [`member-order-utf16`](statements/v70c03756e24bf80d.json) | valid |  | [`v70c03756e24bf80d`](arguments/v70c03756e24bf80d.json) | member names U+FF04 and U+1F4B6, which sort one way by code point and the other by UTF-16 code unit |  |
| [`member-order-code-point`](statements/v2284940a27344c18.json) | invalid | `args-hash-mismatch` | [`v2284940a27344c18`](arguments/v2284940a27344c18.json) | the same arguments hashed with member names in code point order, as Python's sort_keys writes them | `member-order-utf16` |
| [`redacted-with-hash`](statements/v4ce5d82405dae406.json) | valid |  |  | redacted: arguments recorded and withheld, args_hash commits to them |  |
| [`unavailable`](statements/v29a3a6bc8748b8dc.json) | valid |  |  | unavailable: the producer could not read the arguments, no args_hash |  |
| [`not-recorded`](statements/vcbe83ce9abf4720f.json) | valid |  |  | not_recorded: the producer chose not to record the arguments, no args_hash |  |
| [`redacted-without-hash`](statements/v23495c55a6546e67.json) | malformed | `args-hash-required` |  | redacted with no args_hash: the same call as not-recorded except for the state, and refused | `redacted-with-hash` |
| [`recorded-without-hash`](statements/v495ecfd0aeb47262.json) | malformed | `args-hash-required` | [`v495ecfd0aeb47262`](arguments/v495ecfd0aeb47262.json) | recorded with the arguments disclosed and no args_hash | `recorded-integer-amount` |
| [`not-recorded-with-hash`](statements/v2a767498599c917d.json) | malformed | `args-hash-forbidden` |  | not_recorded carrying an args_hash, a commitment to arguments it says it never kept | `not-recorded` |
| [`unavailable-with-hash`](statements/v69fbd962dcd3778c.json) | malformed | `args-hash-forbidden` |  | unavailable carrying an args_hash over arguments it says it could not read | `unavailable` |
| [`state-absent`](statements/vab9485aaa1cc16c6.json) | malformed | `args-state-missing` | [`vab9485aaa1cc16c6`](arguments/vab9485aaa1cc16c6.json) | args_hash with no args_state: the tool call exactly as the v0.1 RFC example writes it | `recorded-integer-amount` |
| [`state-unknown`](statements/va212e7ca11bb10d3.json) | malformed | `args-state-unknown` |  | args_state of omitted, a value outside the closed set | `not-recorded` |
| [`hash-uppercase`](statements/v4e1507f009cbc80d.json) | malformed | `args-hash-format` | [`v4e1507f009cbc80d`](arguments/v4e1507f009cbc80d.json) | args_hash in uppercase hex | `recorded-integer-amount` |
| [`hash-unprefixed`](statements/v3fff2fc0450878c2.json) | malformed | `args-hash-format` | [`v3fff2fc0450878c2`](arguments/v3fff2fc0450878c2.json) | args_hash as bare hex with no sha256: prefix | `recorded-integer-amount` |
| [`payload-edited-after-signing`](statements/v1e0f8f6020f36e17.json) | invalid | `signature-invalid` | [`v1e0f8f6020f36e17`](arguments/v1e0f8f6020f36e17.json) | decided_at moved one second after the envelope was signed | `recorded-integer-amount` |
| [`statement-type-v0-1`](statements/v6e2e4e1f955a996f.json) | malformed | `statement-malformed` | [`v6e2e4e1f955a996f`](arguments/v6e2e4e1f955a996f.json) | the statement _type of in-toto Statement v0.1 | `recorded-integer-amount` |
| [`decision-outside-set`](statements/v2014ef47ee7cee4e.json) | malformed | `predicate-malformed` | [`v2014ef47ee7cee4e`](arguments/v2014ef47ee7cee4e.json) | a policy evaluation whose decision is maybe | `recorded-integer-amount` |
| [`tool-calls-empty`](statements/v9bf8cf8798d17bd4.json) | malformed | `predicate-malformed` |  | a decision record naming no tool call | `not-recorded` |

## Rules

| rule | what it requires |
| --- | --- |
| `signature` | the envelope's one signature verifies under the producer key over PAE |
| `statement` | the payload is an in-toto Statement v1 naming the agent-decision predicate type |
| `predicate-shape` | every field the RFC marks required is present with its type |
| `args-state` | every tool call carries args_state from the closed set |
| `args-hash-presence` | recorded and redacted calls carry args_hash; the other states carry none |
| `args-hash-format` | args_hash is sha256: followed by 64 lowercase hex digits |
| `arguments-json` | the disclosed arguments of a recorded call are one JSON object |
| `arguments-duplicate` | no object in the disclosed arguments repeats a member name |
| `arguments-integer` | an integer literal lies inside the RFC 7493 range, +-(2**53 - 1) |
| `arguments-overflow` | a number with a fraction or exponent is a finite double |
| `args-hash-match` | args_hash is SHA-256 over the RFC 8785 bytes of the disclosed arguments |
