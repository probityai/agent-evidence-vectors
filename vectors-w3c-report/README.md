# v0.1 per-check report conformance corpus

The conformance set for v0.1 of the per-check reporting format of the W3C
public-agent-conformance community group, as the v0.1 text of 30 September
states it (list message `0087`, the copy the text names as canonical,
vendored under `spec-vendored/`), as whole reports. Every row of the section 4
rejection table, rows 1 to 14 under the numbers and classes v0.1 gives them, is
backed by a member that must be rejected under that row alone and a member
that must pass, and so is every rule v0.1 states outside the table: the cause
vocabulary and the qualifiers (section 1), the evidence object (section 2),
carry or reference and digests over a collection (sections 3 and 3.1), and the
roll-up (section 5), the control binding of section 5.4 included. Each row is
anchored to the v0.1 sentence it tests. The same manifest carries members of
two further subject types, the Run object of
`draft-arsentev-agent-run-metrics-00` and the discovery snapshot of
`draft-arsentev-llm-context-discovery-00`, judged by their own sentences.

## Where the corpus and the v0.1 text differ

Section 10 of v0.1 says the text governs where the two differ. The three
changes the corpus carried as proposed while the text was in comment (row 4
read as the cause value `confinement-failed-during-check` under `void`,
`RFC9162_SHA256` in the closed set of tree shapes, and the section 5.4 control
binding, `W3C-R-029`) are in the v0.1 text and are agreed here. What remains:

- `W3C-R-022`, the coverage block of `0001`, is not in v0.1 and is marked
  proposed.
- The run-metrics and context-discovery members are judged by their drafts,
  not by v0.1.
- A run that declares no checker and constraint-set binding is not refused
  under `W3C-R-029`, because v0.1 fixes no slot for it (section 5.5, open item
  O7).

## The text is vendored and every identifier is a sentence

The list messages, the v0.1 text and the two drafts carry no requirement
identifiers. Each
row here quotes its normative sentence, `gen_vectors.py` locates that sentence
in the vendored copy under `spec-vendored/`, records the line it derived, and
hashes the bytes; `MANIFEST.json` pins every vendored file by sha256 and names
its author and source. A reword stops the build rather than re-pointing the
members that cite the sentence. `INDEX.md` lists every requirement with its
digest and every member with the row it is rejected under.

## The reading table is members, not prose

A referenced observation carries a locator and a digest and no outcome. Every
report member carries `resolves`, the store its reader resolves references
against, keyed by locator, so the three lines of carry-or-reference are each a
member: resolves with matching digests (the outcome is read and `moved`
recomputes), resolves with a mismatch (an integrity failure), does not resolve
(unchecked, and the rows reading `moved` degrade rather than fire). The store
is part of the member's identity, so a changed store is a changed member.

## Two readers, held identical

`aee-verify vectors-w3c-report/` judges the corpus through
`corpora/w3creport.go`, and `python3 packaging/run_vectors.py --corpus
vectors-w3c-report` judges it through
`packaging/agent_evidence_vectors/w3creport.py`; the run-metrics and
context-discovery members have their own modules on both rails.
`scripts/w3c-rails-parity-test.py` diffs every line the two print over the
committed corpus and over mutated copies.

## The mutation sweep

`MUTATION-SWEEP.md` is regenerated with the vectors: each row is relaxed in
turn and the corpus replayed, and the table records that only the members
naming the row flipped. The generator refuses to write a corpus in which any
row leaks.

## The 42 pairs

Family `w3c-f-disensor` re-cuts the 42 delta-related pairs a participant
counted in his own corpus at the commit the manifest names, each once as it
was emitted before the freeze, rejected under the declared-slot rule with its
cause, and once against v0.1, accepted. `origin/derive_pairs.py` derives the
pairs from that repository and the checker it pins; the JSON it wrote is
committed beside it and the generator reads only that. Each pair's two
observations are referenced by commit, vector and digest and resolved through
the member's store, never declared in the reference, and the reports declare
the disensor domain once, at run level.

## The appendix and the emitter

`docs/W3C-V01-CONFORMANCE-APPENDIX.md` is rendered from the manifest by
`scripts/gen-w3c-appendix.py`. The reference emitter is the same Python
module: `agent-evidence-vectors --emit-w3c-report PATH` writes a v0.1 report
from the harness's own conformance report, under the crosswalk the module
states, and the report it writes from the AEE corpus conforms.

The report that emitter wrote from the AEE corpus as released at 0.12.0,
the run section 9.1 of the v0.1 draft refers to, is published under
`observed/aee-v0.12.0/` with the harness report it was written from and a
`RUN.json` recording the command, tag, commit and wheel digest. The manifest
pins all three files in `referenceEmitterRuns`, generated from `RUN.json`, and
both readers refuse the corpus if a file is missing, its bytes have changed, or
the validator would reject the report. `observedRuns` stays reserved for runs by
an implementation this repository did not write.

Regenerate byte-identically: `python3 gen_vectors.py`. Refuse a drifted tree:
`python3 gen_vectors.py --check`.
