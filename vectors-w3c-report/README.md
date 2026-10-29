# v0.1 per-check report conformance corpus

The conformance set for v0.1 of the per-check reporting format of the W3C
public-agent-conformance community group, as the v0.1 text states it (list
message `0087`, the copy the text names as canonical, vendored under
`spec-vendored/`), as whole reports. Every row of the section 4 rejection
table, rows 1 to 14 under the numbers and classes v0.1 gives them, is backed by
a member that must be rejected under that row alone and a member that must
pass, and so is every rule v0.1 states outside the table: the cause vocabulary
and the qualifiers (section 1), the evidence object (section 2), carry or
reference and digests over a collection (sections 3 and 3.1), and the roll-up
(section 5), the control and prior-run bindings of section 5.4 included. Each
row is anchored
to the v0.1 sentence it tests. The same manifest carries members of two further
subject types, the Run object of `draft-arsentev-agent-run-metrics-00` and the
discovery snapshot of `draft-arsentev-llm-context-discovery-00`, judged by
their own sentences.

[![Checked with Probity](https://img.shields.io/badge/checked-with_Probity-0969da?logo=data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAMAAABEpIrGAAAAkFBMVEX8%2B%2Bzr5NPgyrfKyLnSq5Wzo4tWltqRkZI2kPU1kvk1j%2FMwkPgzjfI2jO80jO40jO3MdWOZc1SLblN1aFxxXFJzVDY2i%2B40i%2B00i%2Bw0i%2Bs0ius1iOZAapwugNYtdbUqaq0qV4tkRzJXOB47Oz43JRkjNEYiHBwlFxIfFxMcEg0XEQ0WEAwXDAUWCAEOCQcJAgCa503RAAAB3klEQVR42rWT2ZacIBCGceHYoN240SK2Crig4vL%2BbxfszJyZTmaSm6S4rI9a%2FwK3vxj41wDj5E9AwS%2Foxjn7DmARqgVHCBHyJcBxJeZtEG2Nv4hAGEPXYVumddvWAbFfgJJECDfDukxa63ldmw%2FiCTCEK%2BteFzNbQI%2BbQPwzwKJGjNO2LMacxNqK1wgcNfO2mqfbHMs8NEkeXT8AjurRTKfbMlqOa5vFyc8cZclu4PSvWptlPlOMeb4PsQu78MoYQWFIwKUet0nPZl%2FMki1H3x%2FKd1PVhhdkS2tDgM7m9bR3XX8EXtYde59SSVVXNx2NMwuIbbGl74HUu%2BcFXrArSpXqlVSpGz8sUG%2FjoCej1RHA6ZAgl1SmUvVUQjduEGDIdt0MxuwjCHYNAZSwT1IbhaZ%2BFt7BrUAXbguxnx3gZ9AJVJLal0hKaYv4OShGbu249Z4F4jhQ1PcpTUYLDBF5WxZB9dBB14O%2Bm6eu48QQpjBXIizf113iS9sF0LYxZMD1PODbVvtznu96sGOrWyFEiwQEwHNcC8gaF58UxfG1qiqMqzx2AACJ0i0qXyRXEIwjwnD1SBOYdKJ%2B7vxF1eRUaxGF9ePRVgiX3xxOccdhiK5v6v%2Fysgp2Z%2BR%2F3ebv9gP5RU8tSdZhDwAAAABJRU5ErkJggg%3D%3D)](https://github.com/probityai/probity)

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
  under `W3C-R-029` or `W3C-R-033`, because v0.1 fixes no slot for it (section
  5.5, open item O7).
- v0.1 does not say which bytes a digest over a JSON value is taken over. The
  digest encoding below, `W3C-R-030` to `W3C-R-032`, was proposed on the list
  after the text froze and is marked proposed.

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

## Three readers, held identical

`aee-verify vectors-w3c-report/` judges the corpus through
`corpora/w3creport.go`, `python3 packaging/run_vectors.py --corpus
vectors-w3c-report` judges it through
`packaging/agent_evidence_vectors/w3creport.py`, and `readers/w3c-report-rs`
is a Rust reader written from the v0.1 text and the corpus alone
(`docs/research/w3c-reader-independence.md`). The run-metrics and
context-discovery members have their own modules on each rail.
`scripts/w3c-rails-parity-test.py` diffs every line the three print over the
committed corpus and over mutated copies.

## Digests over a JSON value: jcs-sha256

A report digests JSON values: each check of the check set is one leaf of the
`check-set` root. Every reader takes such a digest over the RFC 8785 form of
the value under a numeric profile, the encoding the list named `jcs-sha256`
(`2026Oct-0038`, with the profile from `2026Oct-0040`):

- **Strings.** Only the quotation mark, the backslash and U+0000 to U+001F are
  escaped, with the short forms `\b \t \n \f \r` where JSON has them and
  `\u00xx` in lower case otherwise. Every other character, U+007F and
  everything above it included, is written as itself in UTF-8.
- **Member names** are sorted by their UTF-16 code units, so a name starting
  with U+1F600 (lead surrogate 0xD83D) sorts before one starting with U+FB33.
- **Numbers.** A number is admitted when its exact decimal value is an integer
  of magnitude below 2^53, that is from -(2^53-1) to 2^53-1, and it is written
  as that integer whatever its spelling: `1.0` as `1`, `1e2` as `100`, `-0` and
  `-0.0` as `0`. A number whose exact value is not an integer (`0.5`, `1e-7`,
  and `0.99999999999999999`, whose nearest double is 1) has no `jcs-sha256`
  form, and nor has an integer of magnitude 2^53 or more (`9007199254740992`,
  and 10^21 in either spelling). The value is decided on the token, never on a
  double made from it. A value that needs such a number carries it as a string.
- **The refusal.** A report whose digested value holds a number outside the
  profile is rejected under `W3C-R-020` with the cause `non-integer-number` or
  `integer-outside-safe-range`, and a root that does not recompute is rejected
  under `W3C-R-020` with the cause `digests-differ`. The Python module's
  `check_set_refusal` writes the finding with the number as it was written,
  `W3C-R-020 (integer-outside-safe-range: 1e21)`.
- **The declaration.** A set binding may state `"digest-encoding":
  "jcs-sha256"`, the one member of a closed set. A binding that states none is
  digested under `jcs-sha256`. A binding that states anything else is rejected
  under `W3C-R-015` with the cause `unsupported-digest-encoding`, never read as
  if it had named the reader's own encoding.

A reject member of these families states its cause in `expected.cause`, and
every reader checks that its rejection names that cause: a number outside the
profile and a root that does not recompute both land under `W3C-R-020`, and
only the cause tells them apart.

A member identifier is `v` and the first 16 hex digits of SHA-256 over the RFC
8785 form of the member's `kind`, `family`, `requirements`, `subjectType`,
`subject`, `resolves` and `expected`, a missing field read as null. It takes
numbers as RFC 8785 writes them, as IEEE 754 doubles, and not under the
profile, because a member rejected for carrying a number outside the profile
still needs a name.

The readers used to write compact, sorted-key, ASCII-escaped JSON. Every
identifier and every root committed before these members was recomputed both
ways and coincides, because none of them carried a non-ASCII character,
U+007F, a fraction, `-0` or an integer outside the profile. No earlier member
changed.

## The digest-encoding members

Eight families carry the encoding: 14 accept members and 19 reject members.

| family | case | accept | reject |
|---|---|---|---|
| `w3c-f-jcs-u007f` | U+007F written as itself | 1 | 1 |
| `w3c-f-jcs-non-ascii` | U+00E9, U+20AC, U+2028 and U+1F600 as UTF-8 | 4 | 4 |
| `w3c-f-jcs-member-order` | a supplementary-plane name before a BMP name above U+D800 | 1 | 1 |
| `w3c-f-jcs-number-value` | `-0` and `-0.0` together, the integer `-0` alone, and `1.0` and `1e2`, written by value | 3 | 3 |
| `w3c-f-jcs-safe-range` | both boundaries, the neighbours on either side, and numeric strings | 2 | 4 |
| `w3c-f-jcs-1e21` | 10^21 as `1e21` and as digits, and as strings | 1 | 2 |
| `w3c-f-jcs-non-integer` | `0.5`, `1e-7`, `0.99999999999999999`, and numeric strings | 1 | 3 |
| `w3c-f-jcs-declaration` | a declared encoding in and out of the closed set | 1 | 1 |

Each reject member is rejected for its stated cause by all three readers, and
flips when the one rule it rests on is weakened: the encoding section of
`MUTATION-SWEEP.md` weakens each rule of the encoding in turn and records that
only its own members flip. The members rest on proposed requirements, so they
are counted as excluded-under-proposed-rule, beside the `W3C-R-022` members,
and none of them enters the section 10 selection.

The section 10 selection is 169 members, 43 to reject and 126 to accept.
The four added since v0.18.2 are the `w3c-f-33` family: v0.1 change log entry
12 binds the prior-run reference of section 5.4 to the checker and constraint
set of the checks it speaks for, as it binds the control under `W3C-R-029`,
and `W3C-R-033` carries that half, two members to reject and two to accept. At
corpusDigest `f9e58e62f89b0700c94bfae289f73517439008ebd3b655e3d85057b2ec7668fc`
(v0.18.1 and v0.18.2) the selection was 165 members, 41 to reject and 124 to
accept. Before v0.18.0 it was also 165 members, but 83 to reject and 82 to accept, at
corpusDigest `f00d4443f14881b4102693da0b73ecc7524b7410aec25fe9dbef077e7f73f1fe`
(v0.17.4 to v0.17.6), and the same members at corpusDigest
`76a189e2a73f1f635bc555176ca9660c988540f3e86e9d4f8dab64ebec47cc0d`
(v0.17.7 to v0.17.9). The 42 pairs below account for the whole difference:
v0.18.0 moved the as-emitted member of each pair, 42 reports in all, from
reject to accept. A section 10 sentence that pins either older digest asks an
implementation to reject those 42 reports, which v0.1 accepts.

## Recompute a member's digest by hand

A leaf is the `jcs-sha256` bytes of one check. A `flat` root is SHA-256 over
the concatenated SHA-256 of each leaf, in order; `rfc6962` and
`RFC9162_SHA256` are the Merkle Tree Hash of RFC 6962 section 2.1. Member
`v822c4bed9ba714d3` carries two checks, one annotated with U+007F, and its
root recomputes from the corpus directory with `printf`, `openssl` and
`sha256sum` alone (`\177` is U+007F, written as the byte RFC 8785 writes):

```sh
( printf '{"annotations":{"text":"delete \177"},"check":"c-u007f","state":"pass"}' | openssl dgst -sha256 -binary
  printf '{"check":"c-pass-2","state":"pass"}' | openssl dgst -sha256 -binary ) | sha256sum
# fe92923b2a1cdb0f712e0376f2e69c30511cedec57333cea3f5e06c15c9e5df2
```

The output is the `check-set.sha256` the member declares. `INDEX.md` prints
the same command for every member of the eight families, one per member; for a
reject member it prints the root a reader writes with the member's rule
weakened, which is the root the member declares and a conforming reader
refuses.

The member file carries the same information itself, under `canonical`, so a
reader that fails a member learns from the member alone what it should have
produced. `canonical.conforming` holds what a conforming reader writes: each
leaf's bytes in hex with their SHA-256, the flat root over them, and the
command that prints that root; where a conforming reader refuses the report
instead, it holds the refusal. A reject member also carries
`canonical.declared`: the bytes a reader writes with the rule named in
`rule-switched-off` weakened, whose root is the one the member declares. The
block is not among the fields the identifier covers, so it names no member
differently.

## Check the corpus digest from outside this repository

`corpusDigest` is SHA-256 over the bytes of the member files, concatenated in
identifier order. From the corpus directory:

```sh
python3 -c 'import hashlib, json
manifest = json.load(open("MANIFEST.json"))
digest = hashlib.sha256()
for entry in sorted(manifest["vectors"], key=lambda e: e["id"]):
    digest.update(open(entry["file"], "rb").read())
print(digest.hexdigest())'
# prints the corpusDigest in MANIFEST.json
```

Each member file is named after its identifier, so while `vectors/` holds
exactly the listed members, as it does in a release, this gives the same
digest:

```sh
cat $(ls vectors/*.json | LC_ALL=C sort) | sha256sum
# prints the corpusDigest in MANIFEST.json
```

The digest must equal `corpusDigest` in `MANIFEST.json` and the first field of
the `vectors-w3c-report/MANIFEST.json` line of `release/CORPUS-DIGESTS.txt`.
That file is signed: check the signature and its timestamps as
[docs/reference/release-verification.md](../docs/reference/release-verification.md)
says, with `cosign verify-blob` and `release/cosign.pub`.

## The mutation sweep

`MUTATION-SWEEP.md` is regenerated with the vectors: each row is relaxed in
turn and the corpus replayed, and the table records that only the members
naming the row flipped. The generator refuses to write a corpus in which any
row leaks.

## The 42 pairs

Family `w3c-f-disensor` re-cuts the 42 delta-related pairs a participant
counted in his own corpus at the commit the manifest names, each once as it
was emitted before the freeze, with the error list declared moved, and once
against v0.1. Both are accepted. Section 2 of v0.1 says moved is recomputed,
not declared, and rejects an object whose moved is not contained in its
declared compared set; the recomputed moved of every pair is contained, and
section 2.1 says no rejection row reads the recompute-opaque error list. Until
v0.18.0 the readers held the declared moved against the compared set and
rejected the 42 as emitted; the change moved those 42 members from reject to
accept and renamed them. `origin/derive_pairs.py` derives the
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
