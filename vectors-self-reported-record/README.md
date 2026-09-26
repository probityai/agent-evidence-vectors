# Self-reported agent record vectors

**The claim this corpus tests: a record an agent runtime keeps about itself is
refusable on its face, and a verifier that reads such a record's assertions
without requiring the signature an observation would carry accepts every one of
five attacks that already succeeded against a deployed self-reported store.**

Conformance corpus for the contract at
[`spec/self-reported-record/v1.md`](../spec/self-reported-record/v1.md), type URI
`https://probityai.github.io/agent-evidence-vectors/predicate/v1/self-reported-record`.

Eleven members: five accept, six reject, over six conditions. `MANIFEST.json` and
`INDEX.md` are emitted by the generator and carry the identifiers, the verdicts
and the codes; no identifier is written into this file, because an identifier in
prose is a cache with no invalidation and this repository has already paid for
one of those.

## Why a new family rather than a member of an existing one

The nine corpora already here test an adversarial-execution statement, an
agent-action statement, a per-check report, a run record, a binding record, an
anchor stream, a COSE carriage, an ACI deployment and an ACS profile. None of
them models the artifact under test here: a runtime's own account of a session,
made of turns, a memory store, two ledgers, and a block of provenance fields the
runtime received from its caller. So this is its own family, its own contract,
and its own reader on both rails.

Its sibling is the observed-effect predicate, which is the **did** half: a
mutation interval named from a vantage the observed party does not control. The
two share exactly one rule, deliberately spelled the same way in both — the
attesting key must not be a key the observed party can mint — because that is the
one discriminator either of them has that works offline.

## The five attacks, and where each one went

Each was run against a deployed self-reported agent record and each succeeded
there: accepted, or reported verified, with nothing refusing. Find the member in
`INDEX.md` by its condition.

| attack, as run | the record it would have to produce | condition | code |
| --- | --- | --- | --- |
| A transcript no agent produced, submitted against a live session id; the store appended it, chained it to the last honest turn, and a later read rendered it as history | a turn declaring the session's attesting key and signed by another | `srr-c-1` | `turn-unsigned-by-attesting-key` |
| A memory file's bytes replaced on disk with a security instruction inverted, while the verify surface read a signed copy held elsewhere and reported the same digest and the same verified verdict | two digests for one path, and they differ | `srr-c-2` | `memory-digest-not-over-named-path` |
| A second local identity created after the first attestation went stale, and the inverted content re-attested under it; verification returned verified, correctly, because there was no notion of an authorised signer | an attesting key the record's own declaration puts inside the runtime | `srr-c-3` | `attesting-key-in-self-signers` |
| A recorded change removed, after which the change log re-folded into a shorter consistent history while the session ledger still named the removed change as a live turn, and the rebuild command was additive | two ledgers in one record naming different change sets | `srr-c-4` | `ledger-members-disagree` |
| Twelve provenance fields persisted from one unauthenticated call — a fabricated model, token counts, cost, step count, reasoning transcript and reasoning signature — with no cryptographic signature over the turn record at all | the same twelve values, each declaring a coverage nothing carries | `srr-c-5` | `field-claims-coverage-uncovered` |

The twelve field NAMES in the generator's `CALLER_FIELDS` are the names that
store actually persisted, nine as exact echoes of the caller's own JSON and
three renamed or re-encoded. The values beside them are synthetic: a conformance
corpus has no business carrying somebody's real record.

## The pair that carries the argument

`srr-c-5`'s accept member and its reject member carry **the same twelve
caller-supplied values**. One declares each of them `producer_asserted` and is
ACCEPTED. The other declares each of them `substrate_covered` and carries nothing
covering them, and is refused.

That is the whole thesis in one mutation. Carrying a value the caller supplied is
not a defect and this corpus does not treat it as one: a runtime that says plainly
"this came from my caller and I did not observe it" has written an honest record,
and the honest record is an accept. What is refused is the same value wearing an
observation's clothes.

The sibling AEE corpus already turns on which key signed a covering record, so
that is not the new part and this corpus does not claim it. The new part is that
the partition is declared PER FIELD, by the record, about itself: twelve values,
one declaration each, and the verdict turns on the declaration with nothing else
changed. That is the axis `field_evidence_partition` was registered for, and this
is the first corpus here that forces it.

## The sixth reject member, named for what it is

`srr-c-6`'s reject member carries an `originKind` value the registry does not
define and is otherwise entirely honest. It is not a finding and it models no
attack. It exists so `rule_wellformed` is reached by some input, because a rule
no member reaches is a sentence rather than a gate, and while it stands unreached
the suite reports a pass for a rule nothing ran. `mutation_check.py` is what
holds that property, and this member is what lets it hold for the one rule the
five attacks do not touch.

## Where the closed vocabularies come from

Five members of each record are values of terms registered in
[`agent-evidence-vocabulary`](https://github.com/probityai/agent-evidence-vocabulary):
`origin_kind`, `attestation_tier`, `observation_vantage`,
`observation_directness` and `field_evidence_partition`. The registry is the
definition and the contract is a consumer of it.

**The registry defines those axes and it defines no refusal code.** So the six
codes above are this corpus's reference verifier's own vocabulary, in exactly the
sense `vectors/MANIFEST.json` already states for its own set: a rail that reaches
the same verdict under a different code has produced a reason-parity datum, not a
failure. `verdict` is normative here and `codes` are measured. Saying so is not a
formality — a corpus that scored on codes would hide the divergences worth
finding, which are the members two rails both refuse for different reasons.

## Running it

```sh
# Rebuild every member from the generator. Byte-identical on every machine.
uv run --extra generators python vectors-self-reported-record/gen_vectors.py

# Rail one, Python: do the committed bytes BEHAVE as MANIFEST.json claims?
uv run --extra generators python vectors-self-reported-record/check_vectors.py

# Is every rule in that verifier load-bearing?
uv run --extra generators python vectors-self-reported-record/mutation_check.py

# Rail two, Go: the same eleven members, a second independent implementation.
go build -o aee-verify ./cmd/aee-verify && ./aee-verify vectors-self-reported-record
```

Both rails agree on all eleven members, on the verdict and on the code.

## What each harness asks, and why there are three

`check_vectors.py` carries the reference verifier and the corpus's check of
itself: whether each member is refused with the code its manifest entry names,
whether every condition a reject member cites is also cited by a member that must
be ACCEPTED, and whether every reject member names the accept member it is one
mutation from. The twin rule is what makes the suite scoreable — a corpus of
refusals gives full marks to a verifier that refuses everything, and the twins
turn that strategy into a zero.

It also asks something the other corpora here do not: **every reject member must
trip exactly one rule, and every accept member exactly none.** A member failing
two rules cannot tell a reader which one its published code refers to, which is
the property the whole code column exists for. All six reject members trip
exactly one.

`mutation_check.py` asks the question a green suite cannot answer about itself:
would any member still be refused if the rule were not there? It disables one
rule at a time and requires that at least one member the full verifier refuses is
then accepted, and that no accept member becomes refused. Six rules, and exactly
one member frees for each. The sibling observed-effect corpus ran this same
harness first and it found four inert rules and one dead clause in the predicate
itself on the first run; this corpus was built with that result in hand.

`corpora/selfreported.go` is the second rail, run by `aee-verify`. Its six rules
are the Python verifier restated rather than imported: two independent spellings
of one rule set is the only arrangement that finds a rule both implementations get
wrong the same way. `corpora/readers_test.go` runs both halves over this corpus —
the committed corpus judged clean, and one byte flipped in one member judged dirty
with the member NAMED.

## The unforced surface, stated rather than left out

Every rule is reached by a member. Not every CLAUSE inside a rule is, and a
corpus that reported only the first fact would be overstating the second.

| rule | the clause a member forces | the clauses no member reaches |
| --- | --- | --- |
| `rule_wellformed` | an unregistered `originKind` | the other three closed vocabularies, every required-member absence, the digest and timestamp shapes, the two-ledger minimum, the per-row shapes |
| `rule_turn_attestation` | a signature that does not verify under the attesting key | a turn carrying no `attestedBy` at all, which `rule_wellformed` reaches first |
| `rule_memory_digest_over_named_path` | two digests that differ | none: the rule is one clause |
| `rule_attesting_key_disjoint` | the attesting keyid inside `selfSigners` | none: the rule is one clause |
| `rule_ledgers_agree` | two ledgers naming different sets | none: the rule is one clause, though every member here carries exactly two ledgers, so the three-or-more shape is unexercised |
| `rule_field_coverage` | `substrate_covered` with no `coveredBy` | `coveredBy` whose keyid is in `selfSigners`, `coveredBy` whose signature does not verify, and `producer_asserted` carrying a `coveredBy` |

Each unforced clause is a member somebody could write, and none of them is
written here. The reason to publish the list rather than the count is that a
reader scoring a rail against this corpus is entitled to know which of the
contract's sentences their score does not cover.

## Determinism and the keys

Ed25519 signatures are deterministic ([RFC 8032]), every key is derived from a
published constant, and every timestamp and identifier in the corpus is either a
literal or a digest of a committed preimage. So the corpus regenerates
byte-identically, which `scripts/regenerability-gate.py` checks by regenerating
it into a copy of the tree and comparing.

The keys are **published test keys** and carry no security value. They MUST NOT
be used anywhere but this corpus. A suite a stranger cannot rebuild is a suite
they have to trust, so the recipe is:

    seed(role) = SHA-256("agent-evidence-srr-test-key/<role>/v1")

with `keyid = SHA-256(raw 32-byte public key)`, and `<role>` one of the five
published names:

| role | what it is for |
| --- | --- |
| `session-attestor` | the key the honest records attest their turns under, outside `selfSigners` |
| `field-observer` | the key that covers a `substrate_covered` field, outside `selfSigners` |
| `observed-runtime` | the key the observed runtime holds; always inside `selfSigners` |
| `second-self-minted` | the second identity the runtime minted, inside `selfSigners`; the attesting key of the `srr-c-3` refusal |
| `forger` | signs the forged turn of the `srr-c-1` refusal, under the attestor's declared keyid |

## Verdicts

Three: `valid`, `invalid`, and `malformed`. `malformed` is stage one and
byte-pure — a defect in the carried bytes that no rule reading a member for
meaning ever reaches. `invalid` is a well-formed record whose own carried
evidence refuses its own claim. An implementation that collapses the two scores
zero on the member that distinguishes them rather than passing by accident.

## What this corpus is wired into, and what it is not

Wired: `aee-verify` through a registered reader; `corpora/readers_test.go` on both
halves; `scripts/regenerability-gate.py` as a generator with its owned files
declared; `scripts/vector-distinctness-gate.py`, which holds that no two
identifiers here address one statement; `scripts/release-digests.py`, which
recomputes this corpus's digest from `digest.py` rather than reading it from the
manifest, and writes it into `release/CORPUS-DIGESTS.txt`; the `[tool.pyright]`
include list, which `scripts/typecheck-gate.py` refuses to pass while any Python
file sits outside it; and the `ruff` invocation in `.github/workflows/ci.yml`,
whose argument list named directories and so did not reach a new one.

Those last two were not foresight. `typecheck-gate.py` named all five files here
as sitting outside every checked directory, and `ruff` over this directory
reported eight findings including three functions past the complexity ceiling,
because the workflow's `ruff` line lists directories by hand and a list like that
is correct only on the day it is written. Both are now inside the scope whose
name already implied them.

**Not wired: `scripts/surface-leakage-gate.py`, and the reason is that the
measurement would not mean anything here.** That gate trains a classifier on a
corpus's surface and reports an out-of-sample AUC against a target of 0.55. On
eleven members a single fold is two or three statements, and an AUC over that is
noise wearing a number's clothes — which is worse than no number, because a
figure that cannot be wrong cannot be trusted either. The two specific leaks that
gate was written for are closed here by construction rather than by measurement:
every member is named after a digest of its own bytes, so no identifier predicts
its own verdict, and there is no directory or prefix per verdict. Registering this
corpus there is the right move at the size where the fold is real, and it is not
this size.

`release/CORPUS-DIGESTS.txt` now carries a line for this corpus. Its detached
signature and timestamps cover the previous contents and are therefore stale by
exactly this change; re-signing is the release lane's, not this one's.

[RFC 8032]: https://www.rfc-editor.org/rfc/rfc8032
