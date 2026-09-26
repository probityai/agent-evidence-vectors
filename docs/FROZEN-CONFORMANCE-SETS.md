# Frozen conformance sets, per specification revision

## The property we do not have

`vectors/MANIFEST.json` carries a `suiteRevision`, and `vectors/CHANGES.md`
carries one entry per revision. Between them a reader can say what the corpus
contains today and what it contained at any earlier revision. Neither says which
vectors an implementation had to pass to **conform to a specification revision**,
and those are different questions.

The difference shows up in a claim this repository already publishes. `README.md`
records an outside Rust rail scoring the whole corpus "with its build frozen
before the corpus moved", and the run ledger in `RUNS.md` keeps the revision
beside every posted figure precisely because "a figure without a revision is a
figure about nothing". Both are careful about the revision. Neither can answer
the next question a reader asks, which is what that revision *required* — because
the only durable record of a revision's membership is the changelog prose, and
prose is not a set.

So the corpus can be re-run and the historical figure can be quoted, and an
implementation that conformed cannot be re-measured against the bar it actually
faced. It gets measured against whatever the corpus has accumulated since.

## The mechanism worth copying

`modelcontextprotocol/conformance` ships a dated file per specification revision
under `requirements/`. Its own header states the contract:

> This file is the canonical answer to "which scenarios must my implementation
> pass to conform to 2026-07-28". It is FROZEN: the lists below were fixed when
> the revision shipped and must not be edited afterwards. An implementation is
> measured against the suite as it stood when it was expected to conform, not
> against whatever the suite has accumulated since.

Five properties are doing the work, and each is separable:

- **One file per specification revision, named by the revision.** Not by the
  suite's own version, because the suite moves for reasons that have nothing to
  do with the specification.
- **An anchor to the release that was current when the revision shipped**, with
  its publication date, so the set is a snapshot of a real moment rather than a
  reconstruction.
- **A split by the leg that runs them** — `server` and `client` there, named for
  the subcommand. Theirs deliberately has no authorization-server section,
  because the specification puts that beyond its own scope, and a requirement set
  carries requirements of the thing the specification defines.
- **A `not_scored` list with a reason per entry**, drawn from a closed
  vocabulary: an extension is optional by definition, a scenario added after the
  revision shipped is one nobody could have been passing, and a pending scenario
  is one the suite's own fixture cannot pass yet. All three still RUN. Their
  loader says why: the implementation under test may pass what the reference
  fixture cannot, "and invisible coverage is how gaps hide".
- **The set is the project's contract, not the implementation's configuration.**
  Their loader refuses an arbitrary path and accepts only a bundled revision
  name, so an implementation under test cannot supply its own bar. Their own
  comment separates this from an expected-failures baseline, which belongs in the
  implementation's repository: "a baselined failure is still a failure against a
  requirement set".

## Why this cannot be a manifest field

The obvious small change is a field on `vectors/MANIFEST.json`. It does not work,
and the reason is a property of this repository rather than a matter of taste.

`vectors/MANIFEST.json` is **generated**. `python3 vectors/gen_manifest.py`
writes it, and `scripts/regenerability-gate.py` refuses any committed file that
no generator reproduces byte-identically. A frozen set has to survive
regeneration unchanged and unread; a generated field is rewritten by definition
on the next run. Putting the freeze in the manifest would make the generator the
only thing holding it, and the generator is the file a change to the corpus edits
anyway.

This is worth stating plainly because it inverts the expected answer: the
manifest is the wrong home for a frozen set **because** the manifest is well
gated. The freeze needs a file that is authored once and never regenerated, which
is the opposite of everything else in `vectors/`.

## The smallest change that gives us the property

A new directory of authored files plus one gate. Concretely:

- `conformance-sets/<spec-revision>.json`, one per specification revision, where
  the revision is identified the way `vectors/MANIFEST.json` already identifies
  it — by `specUpstreamCommit` and `specDigest` — rather than by a date we would
  have to invent. Each file carries: the specification digest, the
  `suiteRevision` current when that specification revision shipped, the
  `corpusDigest` at that moment, the sorted list of vector ids required, and a
  `notScored` list whose every entry names a vector id and a reason from a closed
  vocabulary.
- Because vector ids in this corpus are digests of their own bytes, the id list
  **is** the frozen set. No path, no slug and no ordering assumption survives into
  it, so a frozen file cannot drift into meaning a different statement than it did
  when it was written. That is a property the MCP mechanism does not have, and it
  comes free from the content addressing already in place.
- `scripts/conformance-set-gate.py`, refusing four things: a file whose
  `specDigest` no vendored specification matches; an id the corpus does not
  contain; a vector present at that revision and classified in neither list; and
  — the freeze itself — any change to an already-published file, enforced the way
  `docs/FORCING-BASELINE.json` is enforced, by a ratchet over the file's own
  digest rather than by asking people not to edit it.

The reason class enum should be ours rather than theirs, because our corpus has
different shapes to excuse: an `indeterminate/` vector is not scored because the
specification admits more than one reading, which is a category MCP has no
equivalent of, and it must not be spelled `extension`.

## Why this is left as a note

The task this note was written under permitted implementing the change if it
reduced to a manifest field plus a gate. It does not, for the reason in the
section above, and the honest remainder is a new authored directory, a new gate,
a ratchet, a reason vocabulary, and a backfill of at least the revisions against
which outside runs have already been posted. The backfill is the part that needs
a decision rather than a keystroke: the earlier revisions' membership has to be
recovered from git history, and a set reconstructed after the fact is a weaker
artifact than one frozen at ship time. It should say so in its own file, in a
field, rather than looking identical to a set that was frozen when it shipped.

The first genuinely frozen-at-ship set is therefore the next specification
revision, and the reconstructed ones are evidence of a different grade. That
distinction is the same one `RUNS.md` already draws between a blind run and a
directed one, and it is worth carrying here for the same reason.
