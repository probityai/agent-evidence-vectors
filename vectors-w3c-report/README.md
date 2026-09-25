# v0.1 per-check report conformance corpus

The conformance set for v0.1 of the per-check reporting format of the W3C
public-agent-conformance community group, as the editor fixed its scope on
18 September from the handover of the same day, as whole reports: every
rejection row of the consolidated table backed by a member that must be
rejected under that row alone and a member that must pass; rows 13 and 14 under
the numbering the handover proposes, marked proposed; the two additions of
18 September; the rules the freeze list and the editor's restatement carry; the
rules the thread settled beside the table; and the handover's two
record-definition rules, arity recomputed from the delta and the domain
declared once at run level. Each row carries its class under the handover's
sort (consistency, evidence, form), and the five rows the handover left
unclassified carry a proposed class with the vector pair that shows it. The
same manifest carries members of two further subject types, the Run object of
`draft-arsentev-agent-run-metrics-00` and the discovery snapshot of
`draft-arsentev-llm-context-discovery-00`, judged by their own sentences.

## Rules this corpus proposes, pending the editor's v0.1 text

The rules below answer questions put to the v0.1 draft during its comment
window and are marked `proposed` until the editor's text settles them:

- Row 4 reads the cause cell against the state, as row 3 does. The fact that a
  confinement control failed while the check ran is the cause value
  `confinement-failed-during-check`, admitted only under `void`, so the record
  carries no extra cell for it (the construction put to the list in `0077`, in
  answer to the question in `0076`).
- The tree shapes are a closed set, and `RFC9162_SHA256`, the RFC 9942 section
  5.1 identifier for the RFC 9162 Merkle tree over SHA-256, is a member of it.

## The text is vendored and every identifier is a sentence

The list messages and the two drafts carry no requirement identifiers. Each
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

Regenerate byte-identically: `python3 gen_vectors.py`. Refuse a drifted tree:
`python3 gen_vectors.py --check`.
