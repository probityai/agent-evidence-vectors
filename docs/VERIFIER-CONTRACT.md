# The verifier contract

The failure codes, what the harness compares, the code registry and its guarantees, indeterminate vectors, and condition ids. Part of the [agent-evidence-vectors](../README.md) documentation; the [index](README.md) lists every page.

## The failure-code contract

Every rejection carries a stable machine-readable code (`aee/codes.go`).
The deterministic primary code (first in pinned detection order) is the
conformance contract; message text and code order beyond the primary one
are not. A few precedence pins matter to anyone reimplementing the gates.
A missing binding input reports its own member code
(`run-entropy-missing`, `subject-sha256-missing`), not
`run-binding-mismatch`; that code is reserved for values that can be
derived but come out unequal. `records-absent` fires when
`observationRecords` is missing entirely, and `ref-out-of-range` fires
only once records exist. The method cap reads covering records only, so
records that cover nothing do not participate, and the two sealed posture
equalities (pinned digest, arming record's claim) are enforced jointly,
not independently. Signature *verification* failure is never a failure
code; it is a tier outcome. The one signature-shaped question the
byte-pure layer does answer is how many entries the array carries: a
record with zero of them (`record-signatures-empty`) is malformed, since
counting entries needs no key material. An absent member, an empty array
and a member that is not an array at all are that one fault counted three
ways, and the count is asked once over the record set before any payload
is decoded, so a record carrying no signature is settled ahead of a record
whose payload does not decode. That last sentence is this rail's READING and
not a rule the specification states, and it is the one place where saying so
required a third kind of vector; see Indeterminate vectors below.

### What the suite compares

`packaging/run_vectors.py` runs an external verifier as `<cmd> <vector-file>`,
reads the verdict from the exit status, and reads the codes, the recomputed
result and the tiers from the last line of stdout when that line is a JSON
object of the shape `{"verdict": ..., "codes": [...], "result": ...,
"tiers": [...]}`. `--verifier` takes a command line rather than a path, so a
rail whose machine-readable output sits behind a flag needs no wrapper. One
further member is read and is OPTIONAL: `primaryCode`, the single condition the
rail reports when several hold. Nothing in the accept or reject contract reads
it, because that contract compares code sets and says so below; the
indeterminate families read it and a rail that omits it is recorded as having
committed to no reading rather than as failing.

That object has to be **one line**. The harness reads the last line and parses
that line alone, so an indented encoding delivers a line reading `}` and the run
degrades to the exit status, which as the next paragraph says fails every vector
in the suite. This is not a hypothetical: `cmd/aee-verify -json` wrote
`json.MarshalIndent` for as long as the flag existed, and the first time the CLI
this repository ships was pointed at the corpus this repository ships it scored
0 of 186. `scripts/external-rail-gate.py` now runs that exact pairing in CI, and
a clean sweep by the shipped CLI is the gate.

Each vector is run **twice**, through identical argv. The consumer key policy
travels in the environment variable `AEE_SUBSTRATE_KEYS`, holding a path to
`{"substrateObservationKeys": [{"keyid": ..., "publicKeyHex": ...}]}`; argv is
fixed by the contract, so naming a flag would dictate a spelling to every rail
while naming a variable dictates only where to look. The pinned pass answers
`expected.tierWithPinnedKey` and the unset pass answers
`expected.tierWithoutKey`. Two rules only the second pass can ask about are what
the second pass is for: GATE 2's no-TOFU rule, that a consumer with no pinned
key derives `unattested` for every substrate row and never infers the substrate
root from the predicate, and the rule that deriving a tier never moves
`result`. Before the variable existed there was no key channel at all, the
harness recorded `tiers_without_key: None` for every external run, and the
evaluator skips a column it was handed nothing for -- so `ok-024`'s
`tierWithoutKey` read in the MANIFEST as a requirement on every implementation
while binding two first-party rails and nothing else.

What it compares against `vectors/MANIFEST.json` is not the verdict alone. A reject
vector's manifest entry declares an expected code set, and the codes the
implementation emits must intersect it, so a verifier that rejects a statement
for no stated reason fails the vector. An accept vector's entry declares a
`result`, and the recomputed result must equal it. An implementation that answers
with an exit status and nothing else therefore fails every vector in the suite.
That is worth stating plainly, because the runner's own description of its
external rail said the opposite for several revisions, and nothing was checking
the description against the evaluator it described.

The codes are compared as a set. Order carries nothing and message text carries
nothing, so a verifier that reports the first fault it finds and one that reports
every fault it finds both pass the same entry. That is what lets a strict
single-code implementation and a superset-emitting one certify against one
manifest. It is also why the optional `primaryCode` exists rather than the
harness reading the first entry of the set: a harness that inferred precedence
from an order this paragraph tells rails to ignore would be enforcing a rule the
corpus disclaims.

An implementation that would rather keep its own reject reasons is not shut out
of the corpus. It can emit a report in its own vocabulary and compare that report
against a recorded run of itself, which is how the independent checker described
below verifies parity without ever reading these codes. What that route does not
give is the per-condition comparison: two verifiers can agree on every verdict
and still disagree about which condition each statement violated, and that
disagreement stays invisible until the codes are compared. Two of the divergences
this suite has fixed were exactly that shape.

Grading on the intersection has a cost, paid on this side rather than yours: a
code the reference rail emits that the entry does not declare is compared against
nothing at all. `bad-817` declared two and emitted four, and when suiteRevision 28
moved its parent from a caught row to a reconstructed one, one of the two
undeclared codes changed with it and every gate stayed green. Measured before this
revision added `ok-055` and `bad-986`, nineteen of the vectors then shipped were in
that state, with 24 unpinned emissions between them. Those
emissions are now written down, in an `expected.alsoEmits` array on the entries
that carry them, and `scripts/observed-code-closure-gate.py` refuses both an
emitted code that no field declares and a declared one the rail has stopped
emitting.

**This changes nothing you are required to do.** `alsoEmits` records what THIS
rail reports and obliges no other rail to report it; a strict single-code
implementation and a superset-emitting one still certify against one manifest,
exactly as the paragraph above says, and the comparison surface is the same
verdict and result token it has always been. Nothing you emit is compared against
`alsoEmits`, and nothing you omit from it can fail a vector. The gate that reads
it drives the reference rail alone and never runs over an external one, which is
also why the rule lives in a gate and not in the replay harness that external
rails go through. Read the array as a published measurement of our verifier —
useful if you are chasing a reason-parity figure, and safe to ignore entirely if
you are not.

### Two layers, one set of bytes: `statementLayer`

A few entries carry a second verdict, in a `statementLayer` object beside
`expected`. It answers a different question from the rest of the manifest:
not what an AEE verifier must do with the statement, but what an in-toto
**Statement** parser must do with it, before any predicate is read.

Today the field sits on the three members citing `aee-c-109`: the same ok-002
statement with `predicate` absent, set to `null`, and set to `{}`. An **AEE
verifier must reject all three**, with identical codes, because the empty
predicate is missing every member this predicate requires. A **Statement parser
must accept all three**: the framework types `predicate` as optional and says
"Unset is treated the same as set-but-empty"
([`spec/v1/statement.md`](https://github.com/in-toto/attestation/blob/fd2609c16bcb0ac53443e2b4612977f997e8f9a5/spec/v1/statement.md#L62-L66)),
and `spec/v1/statement.md` in this repository records why `null` joins them.
The reference in-toto bindings refused the absent and null spellings until
[in-toto/attestation#598](https://github.com/in-toto/attestation/pull/598), so
running a Statement parser over these three tells you which side of that fix it
is on.

The field is additive and informative. Nothing in the replay harness reads it,
the comparison surface is unchanged, and a rail that implements only the AEE
layer can ignore it. `scripts/statement-layer-test.py` executes the recorded
verdict with a Statement-layer check rather than trusting it, and the generator
refuses a `statementLayer` key that no member cites.

### The registry

The codes are this suite's registry rather than the specification's. The
specification states the conditions and says nothing about what a verifier should
call them, so the spellings, the precedence pins above, and the promise that
neither of those moves are all contracts this repository carries and not that
document. `aee/codes.go` is the enumerated set.

Adding a code takes four things, and `scripts/code-contract-gate.py` checks the
last three mechanically:

- a condition the specification states that no existing code already names;
- a constant in `aee/codes.go`, in the block for the gate that detects it;
- the same spelling in the Python rail, so the two first-party rails share one
  vocabulary rather than two that happen to agree;
- at least one vector that emits it, which bumps `suiteRevision`.

What the registry guarantees:

- a published code's spelling never changes, and neither does the condition it
  names. A changed condition is a new code, not a redefined one;
- a code is never removed while any published `suiteRevision` names it;
- codes are additive across revisions, so a verifier that recognises the set at
  one revision still recognises it at the next;
- precedence is contractual only where this page pins it. Where two conditions
  can hold at once and nothing here decides which is reported, either is
  conformant — and that no longer means no vector. It means an INDETERMINATE
  vector, which declares every reading a conformant rail may take and holds the
  rail to one of them rather than to ours. The reasoning behind each open
  question still lives in `docs/interpretation-decisions-open.md`;
- message text is never part of the contract, at any revision.

### Indeterminate vectors

Two buckets can make two claims. `accept/` says every conformant verifier admits
these bytes and recomputes this result; `reject/` says every conformant verifier
refuses them and names a condition from a declared set. Neither can say that the
verdict is settled and the condition is not, and about some statements that is
the only true thing to say. The specification carries no failure-code vocabulary
at all, and of its own two-stage verification description it says that "the
sequencing itself is informative" (L366-368). Two rails can therefore reject the
same bytes, name different conditions, and both be right.

Saying it by widening a reject vector's expected set does not work: the harness
compares code SETS, so a set naming both conditions is satisfied by either
answer and by a rail that emits both, and the vector stops measuring the
question instead of starting to. `vectors/indeterminate/` is the third bucket.
A member declares a DETERMINED verdict — indeterminacy is scoped to the
condition, because a vector whose verdict were open would certify nothing — and
a set of READINGS, each naming the condition that reading predicts for that
member. A family is the members sharing one reading vocabulary, and the
generator refuses a family whose declared readings no member's answer can
separate.

A rail satisfies three requirements: the verdict; CLOSURE, its answer on each
member is one some declared reading predicts; and COHERENCE, one reading
explains its answers across the whole family. Either answer is admissible. No
answer is not, and neither is a pair of answers straddling two readings, because
the reported condition is then a function of incidental structure rather than of
a policy the rail applies — the shape a primary-code selector that overwrites
rather than sets-if-unset produces, and a shape no single-fault vector can see.

Which reading a rail took is READ and REPORTED rather than required. A rail may
publish an optional `primaryCode` beside its code set, naming the one condition
it reports when several hold; the families read it, and nothing else does. A rail
that publishes only the set has declined to answer — reporting every condition a
statement carries is a legitimate response — and is recorded as committing to no
reading. That report is the point. Both findings this corpus has taken from an
outside reader were divergences five agreeing rails could not show each other,
and a bucket that records which reading each rail took is where the next one
becomes visible without anybody having to arbitrate.

`vectors/indeterminate/INDEX.md` carries the families, the readings, and the
enumeration of what is deliberately NOT in the bucket: the specification's limits
(the passive-sensor producer assertions, the shared-reference evidencing
obligation), the consumer MAY clauses that sit outside the verdict this suite
reads, and the producer options whose verifier handling is forced.

Two codes carry a standing exemption the gate knows about.
`corpus-anchor-mismatch` and `substrate-anchor-mismatch` are consumer-policy
facts rather than validity conditions: they are recorded on the report's consumer
surface and never change the byte-pure verdict, so no single-statement vector can
exercise them, and the gate requires that none claims to.


### Condition ids

A vector cites the specification rules it forces as `aee-c-NN` condition ids,
and those ids are the normative link between a vector and the rule it exists to
pin. **The registry that resolves them to spec lines is the condition table in
[`vectors/reject/INDEX.md`](../vectors/reject/INDEX.md), and it is the only one.**
Both index files used to say the table lived in the repository README. It never did, in
any revision, and the effect was not cosmetic: the table that does exist listed
only the ids the reject set happened to use, so 17 ids cited by accept vectors
resolved to nothing at all. The table now covers every id the suite cites, in
either direction, and `scripts/condition-registry-gate.py` fails the build when
a cited id has no row or a row names an id no vector cites.
