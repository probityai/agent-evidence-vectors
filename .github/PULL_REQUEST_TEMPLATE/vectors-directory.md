# A new `corpora/vectors-*` corpus

Use this template only for a pull request that adds a new sibling corpus
directory. A change to an existing corpus is an ordinary pull request and
`CONTRIBUTING.md` covers it.

A corpus here is a normative artifact: every vector in it obliges a third party
to implement a rule. The checklist below is what makes it possible for someone
who trusts neither of us to fetch the bytes and recompute the answer.

## What this corpus is

- **Specification it tests:** <name, and a link to the text>
- **Whose text it is:** <upstream project, or this repository, or a proposal>
- **Directory name:** `vectors-<name>/`
- **What it does not test:** <the sentence a citing author will need>

## Checklist

- [ ] **A manifest** at `vectors-<name>/MANIFEST.json` carrying, at minimum,
      the fields `corpora/vectors-ai-agent-action/MANIFEST.json` carries: the suite name,
      the predicate type, the outcome counts, the specification digest and
      provenance, the comparison surface, and a `corpusDigest`.
- [ ] **The digest is derived, never typed.** It is produced by regenerating the
      manifest, and `python3 vectors/gen_manifest.py` or the corpus's own
      equivalent reproduces it byte for byte.
- [ ] **The digest routine runs for somebody who installed nothing.** If your
      generator imports anything that is not in the standard library, the
      preimage moves into a `digest.py` beside it that imports nothing, exporting
      `corpus_digest(manifest, root)`. Generation may depend on whatever it
      needs; verification may not. `v0.10.0` shipped with a corpus whose preimage
      sat inside a generator importing `cbor2` and `pycose`, so the first command
      the README gives a stranger died with `ModuleNotFoundError` in a fresh
      clone, and `v0.10.1` is that fix. `scripts/scitt-digest-isolation-test.py`
      asserts it from a subprocess that cannot see installed packages, because
      every environment that runs CI has the extras and would pass a check a
      fresh clone fails.
- [ ] **A generator produces every vector file.** No vector is hand-written;
      `scripts/regenerability-gate.py` refuses a committed file no generator
      emits, and it refuses it on the push that adds it.
- [ ] **The specification is pinned by digest**, and the manifest says whether
      those bytes are upstream's as vendored or a proposal this repository is
      putting forward. A corpus that tests proposed text says so in the
      manifest and in every table that cites it.
- [ ] **Each vector names the rule it forces** and where the specification
      states it. A vector that pins an implementation's behaviour rather than a
      document's requirement is a regression test and does not belong in a
      corpus.
- [ ] **An indeterminate vector declares every reading** a conformant verifier
      may take, rather than a reject vector widened to accept both. A widened
      code set is satisfied by either answer and measures nothing.
- [ ] **The counts in the manifest and in any prose agree**, and
      `python3 scripts/count-gate.py` passes. A count in prose is a cache with
      no invalidation unless it is declared, delegated, frozen, or attributed to
      a revision in the sentence around it.
- [ ] **The corpus is registered in the three places that enumerate corpora**,
      each of which refuses an unregistered one rather than skipping it:
      `EXTRA_CORPORA` in `scripts/count-gate.py`, which then reads your three
      counts from your manifest and checks the one sentence your `INDEX.md`
      publishes them in; `RECOMPUTERS` in `scripts/release-digests.py`, so your
      digest joins the signed list a release covers; and the corpora table in
      [`DISTRIBUTION.md`](../../DISTRIBUTION.md), which `scripts/distribution-gate.py`
      holds equal to the tracked corpus set in both directions.
- [ ] **Provenance names you.** Your name is on the commits, and the manifest's
      provenance fields say whose specification text this corpus tracks and who
      authored the corpus. Co-authorship is the normal shape here, not an
      exception.
- [ ] **The full local gate run passes:**
      `uv run --with pyyaml python scripts/workflow-steps-gate.py`. It runs every
      shell step of every workflow in file and step order, and it is loud about
      the steps it cannot run here rather than passing over them.

## What happens next

The corpus is reviewed for whether each vector forces something the
specification actually requires. A vector that settles a question the
specification leaves open is moved to the indeterminate set or dropped, and the
reason is recorded rather than applied silently. If anything is declined, it
becomes a row in [`DISPOSITIONS.md`](../../DISPOSITIONS.md) under a permanent
identifier, in your frame.
