# Observed Effect conformance vectors

Conformance corpus for the predicate at
[`spec/predicates/observed-effect.md`](../spec/predicates/observed-effect.md),
type URI `https://probityai.github.io/agent-evidence-vectors/predicate/v1/observed-effect`.

[![Checked with Probity](https://img.shields.io/badge/checked-with_Probity-0969da?logo=data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAMAAABEpIrGAAAAkFBMVEX8%2B%2Bzr5NPgyrfKyLnSq5Wzo4tWltqRkZI2kPU1kvk1j%2FMwkPgzjfI2jO80jO40jO3MdWOZc1SLblN1aFxxXFJzVDY2i%2B40i%2B00i%2Bw0i%2Bs0ius1iOZAapwugNYtdbUqaq0qV4tkRzJXOB47Oz43JRkjNEYiHBwlFxIfFxMcEg0XEQ0WEAwXDAUWCAEOCQcJAgCa503RAAAB3klEQVR42rWT2ZacIBCGceHYoN240SK2Crig4vL%2BbxfszJyZTmaSm6S4rI9a%2FwK3vxj41wDj5E9AwS%2Foxjn7DmARqgVHCBHyJcBxJeZtEG2Nv4hAGEPXYVumddvWAbFfgJJECDfDukxa63ldmw%2FiCTCEK%2BteFzNbQI%2BbQPwzwKJGjNO2LMacxNqK1wgcNfO2mqfbHMs8NEkeXT8AjurRTKfbMlqOa5vFyc8cZclu4PSvWptlPlOMeb4PsQu78MoYQWFIwKUet0nPZl%2FMki1H3x%2FKd1PVhhdkS2tDgM7m9bR3XX8EXtYde59SSVVXNx2NMwuIbbGl74HUu%2BcFXrArSpXqlVSpGz8sUG%2FjoCej1RHA6ZAgl1SmUvVUQjduEGDIdt0MxuwjCHYNAZSwT1IbhaZ%2BFt7BrUAXbguxnx3gZ9AJVJLal0hKaYv4OShGbu249Z4F4jhQ1PcpTUYLDBF5WxZB9dBB14O%2Bm6eu48QQpjBXIizf113iS9sF0LYxZMD1PODbVvtznu96sGOrWyFEiwQEwHNcC8gaF58UxfG1qiqMqzx2AACJ0i0qXyRXEIwjwnD1SBOYdKJ%2B7vxF1eRUaxGF9ePRVgiX3xxOccdhiK5v6v%2Fysgp2Z%2BR%2F3ebv9gP5RU8tSdZhDwAAAABJRU5ErkJggg%3D%3D)](https://github.com/probityai/probity)

The member count, the split by expected verdict, the conditions and the corpus
digest are in [`MANIFEST.json`](MANIFEST.json), under `vectors`, `counts`,
`conditions` and `corpusDigest`. This page copies none of them.

## What this corpus is for

The predicate states rules. A rule nothing exercises is a sentence. Every member
here exists because some rule would otherwise be untested, and six of them close
an attack the predicate's own attack section constructs against itself.

One member is a shape this repository did not have before. No other vector here
carries a **claim whose own evidence refutes it**. The gap was
found the way gaps like it usually are: by finding the same defect live in
somebody else's verifier, where an evidence check ran only when a producer-set
list was non-empty, so a record could assert one thing and carry the
contradiction of it and still pass the gate. A corpus
with no such member cannot tell a verifier that reads claims from one that
recomputes over evidence. Three members now carry it, in both directions:
`mutation-none-with-a-null-write`, `mutation-observed-without-writes`, and
`self-refuting-mutation-none`.

## Running it

```sh
# Rebuild every member from the generator. Byte-identical on every machine.
uv run --extra generators python vectors-observed-effect/gen_vectors.py

# Do the committed bytes BEHAVE as MANIFEST.json claims?
uv run --extra generators python vectors-observed-effect/check_vectors.py

# Is every rule in the verifier load-bearing?
uv run --extra generators python vectors-observed-effect/mutation_check.py
```

## The three files, and why there are three

`check_vectors.py` carries the reference verifier and the corpus self-check. It
asks whether each member is refused with the specific code its manifest entry
names, whether every reject condition also has an **accept** twin, and whether
each reject member names the accept member it is one mutation from. The twin rule
is what makes the suite scoreable: a corpus of refusals gives full marks to a
verifier that refuses everything, and the twins turn that strategy into a zero.

`mutation_check.py` asks the question a green suite cannot answer about itself:
**would any member still be refused if the rule were not there?** It disables one
rule at a time and requires that at least one member the full verifier refuses is
then accepted. It also requires that disabling a rule never turns an accept member
into a refusal, which would mean the rule was refusing something the predicate
permits.

That harness earned its place on the first run. It found **four inert rules** and
one dead clause in the predicate itself:

| finding | cause | fix |
| --- | --- | --- |
| `rule_shape` inert | it bundled three independent rules, and every input that would have tripped it was refused earlier by a narrower one | split into `rule_required_members`, `rule_closed_vocabularies`, `rule_interval_order`, and three isolating members added |
| `rule_path_scope_literal` inert | the glob member's writes could not start with a literal glob string, so the write-scope rule refused it first | the glob member now carries an empty write set, leaving one rule to refuse it |
| `rule_read_bindings` inert | the zero-length-range member's digest was also wrong under the preimage rule, which fired first | the digest is now correct for the empty range |
| `rule_mutation_coherence` inert | the tier recompute carried a fifth clause that duplicated it | **the clause was removed from the predicate**: a clause no input can reach is a sentence, and while it stood it made the coherence rule look measured when nothing reached it |

Two further attacks on the predicate landed after that, and both were closed by
changing what the observer signs rather than by adding a verifier rule. The prior
commitment originally covered the before-root and a nonce, which left an observer
free to select a permissive `authorityDigest` **after** the interval closed, and
left one signed commitment replayable across two intervals that share a
before-root -- the ordinary case where a read-only interval precedes a write. The
preimage now carries `authorityDigest` and `intervalId` as well. Rewiring for it
surfaced a third instance of the same defect class as the merging override: the
baseline built its commitment before the overrides were applied, so every member
that changed its own identifiers inherited the baseline's and six of them refused
on a digest mismatch they were not written to test. The commitment is now derived
from the finished record, which is what it always described.

A separate defect came out of the corpus self-check before that: the generator's
override **merged** nested objects, so the member built to omit
`priorCommitment` silently kept the baseline's, and the rule it existed to test
had no exercising vector while the suite was green. Overrides now replace, and a
sentinel expresses deletion. A vector weakened by its own builder is worse than a
missing vector, because it reports a pass for a rule nothing ran.

## Determinism and the keys

Ed25519 signatures are deterministic (RFC 8032), every key is derived from a fixed
seed in the generator, and every timestamp is a literal, so the corpus is
byte-identical on regeneration. Verified by hashing the tree, regenerating, and
hashing again.

The keys are **published test keys**. A suite a stranger cannot rebuild is one
they have to trust. The `observedParty` key signs nothing: it exists so
`observedSigners` names a real key identifier and the disjointness check has
something to be disjoint from.

## The blob

The read rows narrate one blob, and `MANIFEST.json` publishes it under `blobs`
beside the keys. The expected verdict of `range-digest-over-bytes-alone` assumes a
verifier that holds that blob. A verifier configured from the manifest with the
observer key and no blob accepts that member, because the range digest is the one
binding it cannot recompute. `read-row-nobody-can-check` is the same rule from the
other side: a read over a blob nobody publishes, and it is accepted.

## Verdicts

Four, not two. `valid`, `invalid`, `malformed`, and the `indeterminate`
member's declared readings.

`malformed` is stage one and byte-pure: a defect in the carried bytes that no
trust input reaches. `invalid` is stage two: a coherent statement whose own rules
refuse its claims. An implementation that collapses the two scores zero on the
members that distinguish them, rather than passing by accident.

The single `indeterminate` member carries an `externalAnchor` whose token this
corpus does not hold. The predicate says a verifier **MAY** check the token and
defines no offline validation rule, so a verifier that ignores the member and one
that refuses for an unresolvable anchor are both conforming. Scoring either wrong
would be this corpus inventing a rule the predicate does not carry. The
predicate's changelog names the version at which that member acquires a normative
reader.
