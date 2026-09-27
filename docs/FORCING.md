# What the corpus forces

How the conformance vectors are replayed, how much of the specification the corpus actually forces, and how dead detectors are told apart from quiet ones. Part of the [agent-evidence-vectors](../README.md) documentation; the [index](README.md) lists every page.

## Conformance vectors

`aee/vectors_test.go` replays the conformance vector suite in this repository
(default `../../vectors`, override `AEE_VECTORS_DIR`): every accept vector
must verify valid with matching result and tier columns under both key
policies; every reject vector must be invalid with the primary code inside
the vector's expected code set, emitting no result and no tiers. The runner
skips with an explicit message when the suite is not yet present. The
pinned-policy key is derived from the published test-key recipe
(`seed(role) = SHA-256("in-toto-aee-test-key/<role>/v1")`). Nothing
private is committed anywhere in this repository.

### What the corpus forces, as a measured number

A vector count is an upper bound on forcing and never a measurement of it. The
evaluator satisfies a vector when ANY expected code in a stage is observed, and
the per-stage column the runner prints is a display rather than a verdict: delete
the `result-vocabulary` emission from the rail and two vectors' gate-0 column goes
FAIL while the suite still reports 281 of 281, exit 0. A rail with no
result-vocabulary check at all clears this corpus.

So forcing is measured instead. `scripts/forcing-gate.py` switches off exactly one
rule in the reference rail, replays every vector, and asks whether the corpus
notices — 808 single-site weakenings of `aee/`, one rebuild and one full replay
each. A rule the corpus never notices losing is a rule no third-party implementer
is obliged to build, whatever the vector count says.

One of those weakenings does not switch a rule off at all. Where the specification
says a rule holds for EVERY member of a carried collection, the rail writes a loop,
and the quantifier operator closes that loop after one member: the rule survives
intact and is applied to a single witness. A corpus that still passes was never
forcing the "every" — it carried one member, or its defective one happened to be
the member the weakened rail still looks at. That is a gap no amount of switching
guards off can see, and the sites it finds are published below with the rest.

[`docs/FORCING-BASELINE.json`](FORCING-BASELINE.json) is the result, held as a
tighten-only ratchet: **465 rules forced, 36 seen-but-tolerated, 302 unforced, 5
unmeasurable.** The four outcomes stay apart on purpose — "we could not measure it"
and "the corpus does not force it" are different claims and only one is a gap — and
four sites carry an annotation saying that "unforced" is the wrong word for them,
three because the weakened rail computes exactly what the original computes and one
because an earlier check reaches it first on every input that could get there. Those
annotations are claims the gate falsifies: an annotated site that is ever killed
fails the build.

CI runs the ratchet on every push over the rules the baseline records as forced —
the complete set where a regression is possible — and sweeps all 808 sites nightly,
which is what can see forcing improve.

**What that campaign cannot see, said here before anybody else says it.** Every
weakening is applied to the reference rail's own source, so the measurement
describes what this corpus notices about that implementation and about nothing
else. A third-party verifier is out of its reach by construction, and the reason
is worth being blunt about: this corpus is a fixed, public answer key. A candidate
handed the path to a vector can read the manifest sitting two directories above
it, or carry a table keyed on the digest of the bytes it was given, and clear the
whole suite without implementing a single rule of the specification. Until the
generators can emit a challenge set on demand that no such table can contain, read
a clean external sweep as evidence that a verifier printed the right answers
rather than as evidence that it computed them.

That baseline is keyed by rail site, which is a fact about one implementation's
source rather than about the specification. The same campaign read against the
normative condition ids the vectors cite — which of the document's own rules this
corpus obliges an implementer to get right, which it covers only redundantly, and
which failure codes a conforming verifier may decline to emit altogether — is
published in [`docs/FORCING-HONESTY.md`](FORCING-HONESTY.md). Every figure
there is derived from the baseline and the manifest by
`scripts/condition-forcing-gate.py`, which CI runs with `--check`, so the published
weak spots cannot drift from the data behind them.

One number on that page is about a corpus that no longer exists: the condition
figure quoted before the page was written, taken over an earlier revision whose
own campaign tables were never committed. It is not remembered there, it is
reconstructed. [`docs/PRIOR-FORCING.json`](PRIOR-FORCING.json) pins the two
git objects it is derived from — a forcing baseline and the manifest of the corpus
the figure names — and `--verify-prior` re-derives the projection from them and
refuses anything but a match, including a blob the history no longer holds. It
needs a full clone, so it runs in the nightly sweep rather than on the push path,
where a shallow checkout could not tell a disagreement from an absent object.

The reconstruction counts three more killed weakenings than that earlier note
records over the same sites, and the page closes the difference rather than
publishing it as a residue. All three sit on the branch a verifier takes when the
consumer supplies no key policy at all — the branch only the second of the two
runs each vector now gets can reach, and the run behind the note made no such
pass. `--verify-prior` derives that set from the pinned baseline, checks it
against the set the record names, and checks that the subtraction lands on the
released figure; the page states the identity and what it does not establish.

### Detector liveness, and the anchor beside every refusal

A check that never fires may be guarding a well-designed boundary or may be
dead, and from outside the two emit the same clean run. The corpus separates
them with a planted stimulus: the manifest predicts what an attack looks like
on the wire, the substrate commits to what it saw, the row asserts the two are
comparable, and the run-end seal names what it attributed. When all of that
lines up for an attack in a class, that class has shown a live detector, and
the claim holds for that class and no other — so the fixtures are per channel
rather than a sample of them. The construction adds no member to the predicate,
`scripts/liveness-probe.py` computes it from any statement, and
[`docs/DETECTOR-LIVENESS.md`](DETECTOR-LIVENESS.md) says what it does not
establish, at the same length as what it does.

Beside that, a discipline the corpus had stated once and checked nowhere. A
verifier that rejects its input unconditionally passes every reject vector ever
written, so every refusal here is paired with a statement that must be
accepted: `scripts/accept-anchor-gate.py` requires each reject vector's parent
to ship as an accept vector, and measures, as a ratchet rather than a claim in
prose, the conditions that only refusals cite. It also checks the sentences
that publish those figures, because the count census skips them on the strength
of naming this gate their owner.

Requiring the parent to SHIP establishes that it exists. The same gate now also
requires the child to BE it: every reject vector is diffed against the accept
vector it declares, over a semantic pre-image in which a derived field --
a signature, a batch root, a run binding, the carried result, a digest of
material the statement also carries -- collapses to a token only where both
sides agree with their own derivation. A vector that is not one mutation from
its parent is refused, named, and its differing paths printed. The handful that
cannot express their fault in one edit are declared in
`docs/MULTI-MUTATION-VECTORS.json` with a reason each, and a row with no reason,
a row for a vector nobody ships, and a row that has stopped being an exception
are all refused too.
