# AI Agent Action v0.1 conformance suite

## Identifiers name the bytes, not the answer

Every member of this suite is named after a digest of its own bytes and lives in
`statements/`, alongside a record sidecar in `records/` where it has one. There
is no `accept/` directory, no `reject/` directory, and no `ok-`/`bad-` prefix.
The verdict is in `MANIFEST.json`, which is where a scoring harness reads it.

This was a defect in this corpus, found by a gate in this repository, and it is
worth stating plainly rather than presenting the layout as though it had always
been this way. Measured over each vector's whole manifest-relative path, a cheap
classifier predicted accept-or-reject from the identifier alone with a
separability of 1.0000 -- a perfect score, because the prefix and the directory
each named the answer and either one alone was enough. A rail could have
certified against this suite without reading a single statement.

After the change the identifier surface measures 0.5245 against a null of
0.5245, which is to say it carries nothing: shuffling the labels produces the
same figure. The whole surface fell from 0.9238 to 0.7810.

It did not fall to chance, and the remaining gap is a second and separate defect
that this change does not fix. Most accept members carry a `contentDigest`
member and almost no reject member does, because the RFC 8785 Appendix B
number-serialization family sits entirely on the accept side with no reject
counterpart, so the presence of one member path still very nearly names the
verdict. That is content rather than naming, it measured 0.7810 against a null
of 0.6458 when the identifier fix landed, and closing it means writing Appendix B
reject members from the same template. It is tracked in `TODO.md`, and the
current figure is the `paths` row for this corpus in
`../docs/SURFACE-LEAKAGE-BASELINE.json`.

Identifiers are not reused. The names this corpus published before are retired
with the vectors that carried them, and no mapping from the old names to the new
ones is published: such a file would list a retired `ok-`/`bad-` name beside a
live identifier for every member, which is the surface this change removed.
Re-run the suite to get current results.


Conformance vectors for the AI Agent Action predicate proposed in
in-toto/attestation#588, tracked at `a5dd509`.

**Every reject member names the text it rests on.** `MANIFEST.json` gives each
one a `basis`: the lines of the vendored specification that make it rejectable
and a quotation from them, which `aee-verify` finds in those lines on every
run, so a re-vendor that moves the text reopens the basis instead of carrying
it forward. At `a5dd509` every reject member rests on #588's own text except
the member-name ordering condition, `aia-c-15`. That one rests on the BMP-only
rule this project offers into the pull request
(`../docs/ai-agent-action-canonicalization.md`), and its basis also cites the
#588 lines that read the other way: #588 admits a well-formed
supplementary-plane character in member-name position and calls rejecting one
over-rejecting. A verifier conforming to #588 alone accepts that member.

The commit is fetchable today. It is the head of `add-ai-agent-action-predicate`
on the fork `elang2/attestation`, which the pull request is opened from, and of
`refs/pull/588/head` in `in-toto/attestation`, so `git fetch origin
pull/588/head` retrieves it; a plain clone does not, because it fetches no pull
refs. That branch has been rewritten before, and an earlier pin of this corpus
became unfetchable when it was. The corpus does not depend on the commit:
`spec-vendored/` carries the text, `MANIFEST.json` pins its sha256, and
`aee-verify` recomputes that digest on every run.

The predicate records AI agent tool invocations as observed by a protocol
intermediary, and the records form a hash chain whose root record's chain hash
serves as the subject digest, so a policy can target a whole audit chain. It
shipped without conformance vectors. This suite is offered into that pull
request rather than alongside it: the vectors certify its predicate, use its
type URI, and are built from its own worked example.

## Chain breaks and profiles

A chain is identified by the chain hash of its root record, and #588 at
`a5dd509` admits two kinds of root: a genesis record, and a `chain_break` whose
`priorHead` is null because the crash also lost the chain state. Three
conditions hold that rule from each side.

- `aia-c-17`: every statement in a segment rooted at a priorHead-null break,
  the break's own Statement included, carries the break record's chain hash.
  The reject members carry instead the identifier of the chain the crash
  abandoned, which is exactly what an attacker restarting the attestor wants a
  policy to see.
- `aia-c-18`: a deployment claiming resistance against a compromised attestor
  forbids `priorHead: null` outright. The reject member is a well-formed break
  with a null prior head; its twin is a break whose prior head is known.
- `aia-c-19`: a break whose prior head is known is not a root, so the chain
  keeps its genesis identifier across it. The reject member re-roots the
  identifier at the break.

Whether a priorHead-null break is acceptable depends on that deployment claim,
and #588 names no place the claim is carried, so a verifier learns it as
configuration. `MANIFEST.json` defines the two profiles under `profiles`, each
citing the lines it comes from, and a member whose verdict depends on the
choice names its profile in `profile`. Its `kind` and `expected` hold under
that profile; a rail runs each such member under the profile it names and says
which profiles it implements. Twins are matched per condition and profile.

## Layout

| path | what it is |
|---|---|
| `statements/` | every member, accept and reject alike, named after its own bytes |
| `records/` | JSONL sidecars, the log lines a chain hash is computed over |
| `INDEX.md` | every member in one table, with its verdict, profile and basis |
| `attacks/` | the harness that produced the corpus, and its artifacts |
| `spec-vendored/` | the specification text the corpus certifies against, and the only surviving copy of it |
| `MANIFEST.json` | machine-readable expectations, counts and corpus digest |
| `gen_vectors.py` | regenerates the corpus byte-identically |

The proposed canonicalization text the member-name member rests on is
`docs/ai-agent-action-canonicalization.md`, adapted from in-toto/attestation#570.

## Why the corpus is built from attacks rather than from the schema

A vector derived from a schema tests that a parser reads the fields the schema
names. It cannot find the case the text does not cover, because it is generated
from the same reading of the text that the implementation has.

So each member here starts from an attempt to break a guarantee the predicate
claims, using only what its text actually pins. Against the text this corpus was
first built from, most attempts succeeded, and the pull request has since closed
every one of them. `attacks/run_attacks.py` reads each verdict off the vendored
text: every attack names the rule that would foreclose it, checks a read-path
control phrase first, and reports SUCCEEDED only when the divergence is
constructible and the rule is absent. Attacks that fail are recorded too,
because an attack that fails against the text tells you the text already closed
something, and that is a result worth keeping rather than a dead end worth
deleting.

The sharpest member is the chain-fork member (`v861f20f3fa63ce2b`, condition
aia-c-6). The chain forks: two records carry the same `previousHash`, so both
branches verify completely, the genesis hash and therefore the subject digest
are identical on both, and a presenter chooses which branch an auditor is shown.
No hash is broken, no second genesis appears, and no checkpoint gap opens. The
text first attacked did not require the predecessor relation to be injective;
#588 now does, in the sentence at lines 700-704 of the vendored text that this
member's basis quotes.

## Running it

```
python3 gen_vectors.py     # regenerate, byte-identically
aee-verify vectors-ai-agent-action/   # self-check, from the repository root
python3 attacks/run_attacks.py
```

`aee-verify` refuses to pass a corpus in which a reject condition has no
accepting twin under the same profile. A suite of rejections alone awards full
marks to a verifier that rejects every input, which is the one verifier that
certifies nothing. It also recomputes what every chain-break member claims: the
root record, the subject digest that root implies, the profile the verdict
holds under, and the basis each rejection cites.
