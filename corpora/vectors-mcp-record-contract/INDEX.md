# Conformance vectors (cross-run record contract)

Every member of this suite in one table. The subject under test is a **run
record**: the artifact a cross-implementation claim rests on, rather than any
protocol message.

This corpus is 15 vectors, of which 7 a conformant verifier must
not fail closed on and 8 it must reject.

The criterion is `../docs/INTEROP-EVIDENCE.md` and `check_run_record.py` is that criterion
as code. This corpus is the checker's own conformance suite, so the criterion
is measured rather than asserted.

**Every member is synthetic.** Each is shaped after a defect observed in
published cross-run claims in open specification threads. None transcribes or
attributes a particular claim, and no party is named anywhere in this
directory: the shape is the thing under test, and a corpus that named parties
would be an accusation with a schema.

**Three columns, because they answer different questions.** `re-checkable`
asks whether a third party can obtain the same result from what is published.
`figure` asks whether the headline agrees with its own counting rule.
`independence` is one of independent, self-report or undeclared, and only the
last of those is a defect. A record can be fully re-checkable, carry a figure
nobody should quote, and be a declared self-report, and folding those into one
verdict is how each of them disappears.

Regenerate byte-identically: `python3 gen_vectors.py`.
Self-check: `aee-verify vectors-mcp-record-contract/` from the repository root.
Check a record: `python3 check_run_record.py records/<id>.json`.

## Conditions

| id | what it requires |
|---|---|
| `mrc-c-1` | The inputs carry an immutable reference. A repository name and a version string name a thing that can change under the claim. Because one project in this area published a tag against the wrong commit and left it in place rather than moving it, which is the honest response and also the proof that a tag can be moved. |
| `mrc-c-2` | The runner carries an immutable reference or a digest. Naming the library it was built on is not naming the runner. Because the driver that loads the inputs and emits the result is the part a third party has to have, and it is the part most often absent while both endpoints resolve. |
| `mrc-c-3` | The invocation is published verbatim. Because a reader who has the inputs and the runner and not the invocation knows what ran and not what was asked of it. |
| `mrc-c-4` | The result is published and carries a digest. A digest over a file nobody else can hold is a claim rather than a comparison. Because the digest is what turns a re-run into a comparison; without the file the digest is a promise, and without the digest the file is an unpinned artifact. |
| `mrc-c-5` | A figure states its counting rule: what the denominator counts, and how a member that was not scored is counted. Because a figure written as N of N is read as N passes, and the same run is honestly describable as N members with no failures when some were deliberately not scored; those are different claims and only one of them is what a reader takes away. |
| `mrc-c-6` | Independence is declared: whether the party that ran the inputs authored them. Because a self-report is worth publishing and is not independent evidence, and a reader cannot infer which one a record is. |

## Vectors

| id | kind | conditions | re-checkable | figure | independence |
|---|---|---|---|---|---|
| `v14d745599996345e` | reject | mrc-c-5 | yes | misleads | independent |
| `v1a24e046d96b0499` | reject | mrc-c-6 | yes | honest | undeclared |
| `v2dc4d0dbfd880265` | reject | mrc-c-1 | no | honest | independent |
| `v4ec0532db09c7a54` | reject | mrc-c-2 | no | honest | independent |
| `v50e907fcb9b806f8` | accept | mrc-c-1 | yes | honest | independent |
| `v58de6293c9625b14` | reject | mrc-c-4 | no | honest | independent |
| `v711b6687a6425d47` | reject | mrc-c-3 | no | honest | independent |
| `v714a7eb9aca0469c` | reject | mrc-c-5 | yes | misleads | independent |
| `v740658c91965f801` | accept | mrc-c-4 | yes | honest | independent |
| `v744318c472f31dab` | accept | mrc-c-1 | yes | honest | independent |
| `v74b9938f39ca94e2` | accept | mrc-c-5 | yes | honest | independent |
| `v8ddcb96b3a0892c3` | accept | mrc-c-6 | yes | honest | self-report |
| `v95396ec402906fb0` | accept | mrc-c-2 | yes | honest | independent |
| `va45cc5fefb1fe725` | reject | mrc-c-4 | no | honest | independent |
| `ve5eb95730b9c0acc` | accept | mrc-c-3 | yes | honest | independent |
