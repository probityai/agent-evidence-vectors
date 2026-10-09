# A third reader for the v0.1 report corpus, and how independent it is

Label: **first-party second implementation, independent code path.** It is not
independent of the author: the same person who wrote the corpus, the Go reader
and the Python reader wrote this one. What it adds is a code path that shares
nothing with the other two readers, so a reading that the text supports and a
reading that only the first two readers share can now be told apart.

## Why it exists

Two readers judge `vectors-w3c-report/`: `corpora/w3creport.go` (via
`aee-verify <dir>`) and `packaging/agent_evidence_vectors/w3creport.py` (via
`packaging/run_vectors.py`). A reviewer on the list called them "the same code
run by a second party, not an independent implementation". The measurement
below agrees with him: on 1,410 members mutated at random, the Go and Python
readers printed identical lines for 1,407 and the same decision for all 1,410.
Two readers that never part on inputs nobody chose are one reading, written
twice.

`readers/w3c-report-rs/` is the third reader. It is written in Rust, from the
text, with no line of the other two in view.

## The code-path check

### Read while writing it

| source | what was taken from it |
|---|---|
| `vectors-w3c-report/spec-vendored/0087-arsentev-2026-09-30-v01.txt` | every report rule: states, causes, qualifiers, rows 1 to 14, the evidence object, carry or reference, section 3.1, the roll-up |
| `vectors-w3c-report/spec-vendored/0001-ives-2026-09-01-coverage-block.txt` | the coverage block fields (`W3C-R-022`, proposed) |
| `vectors-w3c-report/spec-vendored/draft-arsentev-agent-run-metrics-00.txt` | the Run object rows `ARM-R-001` to `ARM-R-022` (sections 3.1 to 3.7 and 3.12, plus section 5 and its subsection 5.1) |
| `vectors-w3c-report/spec-vendored/draft-arsentev-llm-context-discovery-00.txt` | the snapshot rows `LCD-R-001` to `LCD-R-011` (sections 3.1 to 3.3, 4.1, 4.3, 4.4, 7.2, 7.4) |
| `docs/W3C-V01-CONFORMANCE-APPENDIX.md` | which sentence each row identifier is bound to, and the closed tree-shape set |
| `vectors-w3c-report/MANIFEST.json`, `INDEX.md`, `README.md`, the member files | field names and object shapes, each member's kind, expected rejects and cited rows |
| `vectors-w3c-report/observed/aee-v0.12.0/report.json` and `RUN.json` | the shape of an emitted report |
| `scripts/w3c-rails-parity-test.py` | the mutation cases, so the third column runs the same ones |
| the source of `jcs-admit` 0.1.1 (crates.io) | its public API |

### Not opened

`corpora/w3creport.go`, `packaging/agent_evidence_vectors/w3creport.py`,
`packaging/agent_evidence_vectors/runmetrics.py`,
`packaging/agent_evidence_vectors/contextdiscovery.py`, the emitter code in
`packaging/run_vectors.py`, and `vectors-w3c-report/gen_vectors.py`.

One exposure is recorded rather than left out. The differential run below
crashed the Python reader, and its traceback printed four lines of
`contextdiscovery.py` (lines 77, 85, 127 and 169). That happened after every
rule in the Rust reader was written, and no rule changed because of it.

### The one shared interface

The printed line format. Its wording and order were learned by running the
Go and Python readers as black boxes over the committed corpus and over about
fifty single mutations of the manifest and the member files, and reading
what they printed. The line format is the contract the parity test checks, so
the third reader has to print it; nothing that decides a line is shared.

### Shared inputs, which is expected

The corpus bytes, `MANIFEST.json` and the vendored texts are what every reader
judges. Three constructions are not stated in prose anywhere and were recovered
from those bytes by recomputation, not from code:

- the member identifier: `"v"` and the first 16 hex digits of the SHA-256 of
  the RFC 8785 bytes of the member's `expected`, `family`, `kind`,
  `requirements`, `resolves` (null when absent), `subject` and `subjectType`.
  It reproduces every committed identifier;
- the `flat` tree shape: SHA-256 over the concatenated SHA-256 of each check
  record's RFC 8785 bytes. It reproduces every committed `flat` digest. The
  `rfc6962` and `RFC9162_SHA256` roots are the RFC 6962 section 2.1 Merkle
  Tree Hash, from the RFC;
- `corpusDigest`: SHA-256 over the member files' bytes in manifest order.

### Dependencies

`jcs-admit = "=0.1.1"` (admission and RFC 8785 bytes), `sha2`, and
`serde_json`. The other two readers use none of these. `dsse` is not a
dependency: no member of the corpus carries a DSSE envelope, so there is
nothing for it to read.

## Provenance of each rule

| rule in `src/` | source |
|---|---|
| state vocabulary, verdict and non-verdict states | 0087 section 1, 1.1 |
| cause vocabulary (13 values) | 0087 section 1.2 |
| free text refused in place of any closed value (`W3C-R-019`) | 0087 section 1.2, "Free text is refused in place of a disposition" |
| rows 1 to 12 (`W3C-R-001` to `W3C-R-012`) | 0087 section 4, rows 1 to 12, read cell against cell of one record |
| default `unknown` on both qualifiers | 0087 section 1.3 |
| row 11 reads the reference against the report's own evidence list | 0087 section 4 row 11; appendix, row 11 |
| delta-related pair: two observations, fixed checker, constraint set and domain, a stated delta (`W3C-R-024`) | 0087 section 1.3 |
| moved contained in compared (`W3C-R-016`) | 0087 section 2 |
| moved recomputed over the observations (`W3C-R-021`) | 0087 section 2, "moved is recomputed, not declared" |
| row 13 reads recomputed moved and degrades when unresolved (`W3C-R-025`) | 0087 section 4 row 13; section 3 reading table |
| row 14, both observations carried or referenced with digests (`W3C-R-026`) | 0087 section 4 row 14 |
| arity never declared (`W3C-R-027`) | 0087 section 2, "Arity is not a slot" |
| domain declared once, named by identifier (`W3C-R-028`) | 0087 section 2 |
| resolves with a mismatch is an integrity failure (`W3C-R-020`) | 0087 section 3, reading table line 2 |
| a reference with no digest reads as unchecked, not as a mismatch | 0087 section 3: a digest is what tells a match from a mismatch |
| count bound and shape declared from the closed set (`W3C-R-015`) | 0087 section 3.1; appendix, "The tree shapes, as a closed set" |
| the set digest recomputed (`W3C-R-020`) | 0087 section 3.1 and the reading table |
| denominator (`W3C-R-017`) | 0087 section 5.1 |
| completeness populations, empty population not claimable, no-void truth (`W3C-R-023`) | 0087 section 5.2 |
| carried against referenced (`W3C-R-018`) | 0087 section 5.3 |
| negative capability: silence refused, shown-by-run needs a fail, a control must fail over the declared checks (`W3C-R-013`) | 0087 section 5.4 |
| a prior run binds surviving check identity (`W3C-R-014`) and its set (`W3C-R-015`) | 0087 section 5.4, last two conditions |
| control bound to the run's checker and constraint set (`W3C-R-029`) | 0087 section 5.4, second condition; appendix on open item O7 |
| coverage block fields (`W3C-R-022`) | message 0001 |
| `ARM-R-001` to `ARM-R-022` | the run-metrics draft, at the section the appendix lists per row |
| `LCD-R-001` to `LCD-R-011` | the context-discovery draft, at the section the appendix lists per row |

Two readings were fixed against the corpus where the text alone allows more
than one, and each is recorded so it can be argued:

- `ARM-R-011` fires only when each part is itself within `input_tokens`. The
  sentence ("disjoint subsets ... their sum MUST be less than or equal") is
  also broken whenever `ARM-R-010` is, and the corpus's `ARM-R-010` member
  names one row. The reader takes the partition as presupposing that each part
  is a subset.
- `ARM-R-022` and the other subset inequalities read well-typed counters only;
  a negative counter is `ARM-R-009`'s.

## What matched, byte for byte

| comparison | result |
|---|---|
| committed corpus, all three readers | identical output and exit status |
| the twelve mutation cases of `scripts/w3c-rails-parity-test.py` | identical on all twelve, and on the committed case too |
| every committed member identifier recomputed | all identical |
| `observed/aee-v0.12.0/report.json`: rows | none fire |
| same: leaf count and flat digest | 272 and `8777195248be4c35...` recompute |
| same: this reader's re-write against the file | byte-identical, 76,057 bytes |
| a fresh `--emit-w3c-report` from the tree at this branch's base | no row fires; the vector total and the digest recompute; re-write byte-identical, 80,438 bytes |

## Where the readers part

`scripts/w3c-reader-differential.py --rounds 8 --seed 23` mutates one field of
every member per round and runs all three readers. Two of the eight rounds
crashed the Python reader and are not counted; over the other six, 1,410
members:

| pair | identical lines | both refuse as malformed, own words | both reject, one as malformed | both reject, different rows | different decision |
|---|---|---|---|---|---|
| Rust and Python | 986 | 287 | 88 | 23 | 26 |
| Rust and Go | 986 | 287 | 88 | 23 | 26 |
| Python and Go | 1,407 | 3 | 0 | 0 | 0 |

The last line is the reviewer's point, measured. The findings, each with the
reader the text supports:

1. **The Python reader crashes on a malformed snapshot and judges nothing.**
   With `robots.disallow` or `robots.records` set to an integer in one member,
   `run_vectors.py` stops with `TypeError: 'int' object is not iterable` and
   prints no verdict for any member. The Go reader accepts that
   member; the Rust reader refuses it as malformed and judges the other 234.
   The draft makes both members arrays of rules and records, so the Rust
   reading is the one the text supports, and the Go reader accepting it is a
   second defect.
2. **Malformed members the Go and Python readers accept.** Of the 26 different
   decisions, 21 are members the Rust reader refuses and the other two accept:
   a `resources` entry that is a string, `cache_writes` that is a string,
   `delta.changes` that is a string, `step_count` that is a string, a
   `retrieved` list that is a string, and `attributed-to` that is not an
   origin. The Rust reader is stricter, and the shapes it requires are the
   ones the texts define. The other 5 run the other way: the Rust reader
   accepts a Step with no `start` (the other two add `ARM-R-006`), a
   completeness block without its accounting claim (they add `W3C-R-023`;
   section 5.2 says what each claim carries, not that all four are present),
   and an evidence object with no `moved` (they refuse it as malformed;
   section 2 recomputes moved rather than requiring it declared).

   Findings 1 and 2 are resolved on the Go and Python side. Both readers now
   refuse as malformed a mistyped `robots.disallow`, `robots.records`,
   `consumer.retrieved`, `resources` entry, `step_count`, `cache_writes` and
   `delta.changes`, in the Rust reader's words, so a mistyped member fails on
   its own line and every other member is still judged; and a ledger
   `tokens` that is not a non-negative integer now fires `ARM-R-014` on all
   three. `scripts/w3c-rails-parity-test.py` carries a case for each of the
   integer robots field, the string `step_count`, the string ledger tokens and
   the string `delta.changes`. What stays open from finding 2 is
   `attributed-to`: the Rust reader fires `LCD-R-008` whenever the attributed
   origin differs from the origin that served the index, while section 7.2
   forbids only attributing a cross-origin index to the advertising origin,
   so there the Go and Python reading follows the sentence.
3. **Row 14 and a missing observation.** Delete one of an evidence object's two
   observations and the Rust reader adds `W3C-R-026`; the other two do not.
   Row 14 reads "neither carries both observations nor references them with
   digests", so one observation is not both, and the Rust reading follows the
   sentence.
4. **Step order with an unreadable start.** With one Step's `start` not a
   timestamp, the Go and Python readers add `ARM-R-006`, apparently ordering by
   the raw string; the Rust reader leaves the order unestablished and fires
   `ARM-R-019` alone. The sentence orders Steps by when they began, which an
   unreadable instant does not say.
5. **Control binding beside a broken control.** With the control already
   refused under `W3C-R-013`, the Rust reader still reads its binding and adds
   `W3C-R-029`; the other two stop at `W3C-R-013`. Both are defensible; the text
   does not order the conditions.
6. **Duplicate members.** The Rust reader refuses a member file with a repeated
   object member on its raw bytes (through `jcs-admit`); the Python reader reads
   it last-wins and goes on to compare fields that no longer exist. RFC 8259
   leaves repeated names undefined and I-JSON (RFC 7493) forbids them.

None of these touch the committed corpus or the twelve parity cases, which is
why the parity test, by construction, could not find them.

## Reproduce

```
cargo build --release --locked --manifest-path readers/w3c-report-rs/Cargo.toml
readers/w3c-report-rs/target/release/w3c-report-rs vectors-w3c-report
readers/w3c-report-rs/target/release/w3c-report-rs --report vectors-w3c-report/observed/aee-v0.12.0/report.json
python3 scripts/w3c-rails-parity-test.py
python3 scripts/w3c-reader-differential.py --rounds 8 --seed 23
```

## Why there is no row in `docs/INDEPENDENT-RUNS.json`

That file records runs of the AEE corpus by `Rul1an/aee-checker`, one
implementation this repository did not write; `scripts/independent-runs-gate.py`
computes the not-run set over its rows and holds the prose in
`docs/research/independence.md` to it. A run of a different corpus by a reader
the corpus author wrote fits neither its `implementation` field nor its
three-value `runLabel` scale except as `author-produced`, and a row there would
change what that gate computes. The label above is recorded here instead.
