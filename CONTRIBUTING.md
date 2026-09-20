# Contributing

How to propose a change to this suite, what happens to the proposal, and what the
gates will refuse. The decision process over all of this — who decides, what is
never changed, how an objection is answered — is [`GOVERNANCE.md`](GOVERNANCE.md).

Anyone may propose anything. There is no membership, no fee, and no distinction
between an implementer's proposal and the maintainer's.

## Where your change goes

**Read this first, because the most common wasted effort here is a good proposal
filed in the wrong repository.**

| What you want to change | Where it goes |
| --- | --- |
| What the predicate **requires** — a rule, a field, a normative sentence | upstream, in the in-toto attestation project's review of the predicate. This repository vendors a pinned copy and cannot change it |
| What the corpus **forces** — a vector, a boundary case, a missing discriminator | here |
| A **failure code**: a new one, or a precedence question | here |
| A **reference rail** defect — the Go core, the Python rail, the CLI, the attestor | here |
| A **disagreement with something this repository decided**, including a decision already published | here, as an issue. It becomes a row in [`DISPOSITIONS.md`](DISPOSITIONS.md) with its own identifier whichever way it goes |
| Your own verifier's divergence from this corpus | here, as an issue. A divergence is interesting whether or not it turns out to be your bug |

If a proposal belongs upstream, this repository will say so and point at the
thread rather than filing it away.

## Set up a clone

```bash
bash .githooks/install.sh          # once per clone: hooks are local config, nothing inherits them
uv sync --extra dev --extra generators
cp go.work.example go.work         # only if you are building the attestor module
```

The hook installer sets one config key, writes no files, and refuses to switch if
a hook that runs today would stop running. The commit-message gate it installs
runs in CI from the same tracked file, so a clone that skips this step is checked
anyway — the hook exists to stop you finding out by email.

## Run everything before you push

```bash
uv run --with pyyaml python scripts/workflow-steps-gate.py
```

That reads the workflows and runs **every** shell step in them, in file and step
order, and is deliberately noisy about the marketplace-action steps it cannot run
locally. It exists because a change was once pushed after its author read the
first two steps of a three-step guard, ran those two, and saw them pass; the third
step was the one the change broke, the push went red on a public repository, and
the tag cut from it had to be withdrawn. Running the checks you happened to read
is not running the checks.

The same command is what `.githooks/pre-push` invokes. `git push --no-verify`
walks past it and the remote runs the identical workflows regardless.

## What the gates refuse

Most of these exist because the thing they refuse already happened here. They are
worth reading before writing rather than after failing.

| Gate | It refuses |
| --- | --- |
| `scripts/regenerability-gate.py` | a committed file no generator produces. The corpus regenerates into a copy and is diffed; hand-written vectors and hand-written manifest entries fail on the push that adds them |
| `scripts/count-gate.py` | a count typed by hand. Every published count is checked against the one source that derives it, and a **new** count-shaped integer anywhere in tracked prose fails unless it is declared, delegated, frozen with a reason, or attributed to a revision in the sentence itself |
| `scripts/condition-registry-gate.py` | a condition id a vector cites and no registry row resolves, and a registry row no vector cites — in both directions |
| `scripts/spec-drift-gate.py`, `scripts/spec-anchor-gate.py` | a reference into the vendored specification that has come off the prose it was written for. Resolving to a line that still carries text is not enough; a stale reference reads as evidence |
| `scripts/spec-drift-gate.py` | vendored bytes that are not upstream's |
| `scripts/code-contract-gate.py` | prose describing a failure-code behaviour the evaluator does not have |
| `scripts/external-rail-gate.py` | the shipped CLI failing the shipped corpus through the documented third-party contract. Both existed and nobody had run one against the other |
| `scripts/forcing-gate.py` | a corpus that has stopped forcing a rule the baseline records it as forcing. Tighten-only |
| `scripts/independent-runs-gate.py` | prose about what an outside implementation ran that disagrees with the run ledger |
| `scripts/consumer-lag-gate.py` | a corpus change on the default branch that the repositories vendoring it have not carried. Measured against the default branch, because a rail cannot vendor a branch nobody has merged |
| `scripts/dispositions-gate.py` | a disposition row whose revision, vectors or cited record do not resolve, and a published table that is not the one the ledger renders |
| `scripts/coverage-gate.py` | any single file below the coverage floor. Per file, not on average |
| `scripts/complexity-table-gate.py` | a function whose measured complexity has drifted from the accepted-complexity table |
| `.githooks/commit-msg` | a subject over seventy-two characters, any non-ASCII byte, an AI-attribution trailer, or project-internal jargon that will not resolve for a reader six months later |
| `.github/workflows/no-internal-drafts.yml` | internal drafting notes, `DRAFT-` files, tool-state directories, absolute home paths, and first-party product names. This repository is deliberately product-neutral |

**A gate's verdict may depend on the revision under test, and on nothing else on
the machine.** Not on the clock, not on a sibling checkout, not on which files a
previous run left behind, not on the interpreter's hash seed. The test is simple:
run the gate twice at one revision, on two machines or in two processes, and it
must say the same thing. A gate that fails this is worse than no gate, because it
spends its failures on the wrong commits and its passes on questions it never
asked. Three of them were found here on one day:

- `scripts/surface-leakage-gate.py` summed a row's features while iterating a
  `frozenset`. Python salts string hashing per process and floating-point
  addition is not associative, so identical rows tied in one process and ranked
  in another. One corpus measured 0.5304 under most seeds, 0.5343 under others
  and 0.5054 in the run that caught it -- a refusal for a leak that was not
  there, and a refusal for slack that was not there, on an untouched corpus. Sum
  in sorted order.
- `scripts/vendor-remap-test.py` compared the vendored specification against a
  sibling clone's WORKING TREE. A lane reduced that clone's copy from 2322 lines
  to 278 and amended it three times in two hours; three branches went red at
  different times, one of whose only commits were a run-ledger entry and a fix to
  an unrelated gate. Pin the revision in `spec/VENDOR-PIN.json` and read the bytes
  out of an object store, never a working tree.
- The same check printed `SKIPPED` and exited 0 when the clone was absent, which
  is every run on a hosted runner. Absence is not a pass. **A check that could not
  run must exit non-zero and name what was missing** -- and if that means it can
  never run in CI, it does not belong in CI.

**Zero warnings.** A build with a warning is not done. That covers `gofmt`,
`go vet`, `staticcheck`, `golangci-lint`, `mypy --strict` and `ruff` — all of them
run on every push and none of them is allowed to be noisy.

## Adding a vector

A vector is the only thing that obliges a third party to implement a rule, so
adding one is a normative act and the process is heavier than a code change.

Heavier, and still not a code change at all. A vector is data: a statement, the
conditions it cites, and the outcome a conformant verifier must reach. Filing
one requires no edit to the reference verifier's own implementation. The
generator you write it in is a build-time tool that emits those bytes; it is not
the thing under test, and `aee/` is not touched to make a vector pass. If the
reference rail does have to change for the vector to go green, the vector has
found a defect in the rail, and that fix is its own change with its own reason
rather than part of this one.

In this order:

- **Say what rule it forces, and where the specification states it.** A vector
  that pins the reference rail's behaviour rather than the document's requirement
  is a regression test, and belongs in a `_test.go` file instead.
- **Write it in the generator**, `vectors/accept/gen_valid_vectors.py` or
  `vectors/reject/gen_invalid_vectors.py`, never by hand. The corpus is signed
  with published test keys and regenerated byte-identically; a hand-written file
  fails `scripts/regenerability-gate.py`.
- **Add its row to the index table** in the same directory, carrying the
  condition ids it cites and the specification anchor.
- **Regenerate the manifest**: `python3 vectors/gen_manifest.py`.
- **Pin every code the reference rail emits.** Run
  `python3 scripts/observed-code-closure-gate.py`; if it names your vector, add
  the codes it lists to an `(also emits: ...)` clause on the row — in the codes
  cell for a reject vector, in the conditions cell for an indeterminate one,
  because that table has a codes cell per reading and the emission set belongs to
  the vector rather than to any one reading. The clause is a record of what our
  verifier reports and nothing else: it never widens what the vector measures, it
  obliges no other rail to emit the same, and it is checked in both directions, so
  a code that stops being emitted has to leave the clause in the same change.
  Do **not** reach for the `also carries` clause instead — that one is the
  second-fault self-check's exemption key, so a code declared there switches a
  recompute off.
- **Bump `suiteRevision` and write the changelog entry.** The entry states the
  corpus size, what changed, and — this is the part that matters — what the
  revision does *not* exercise. A revision that makes a rule normative over a
  corpus that cannot see it should say so in its own words rather than leaving a
  reader to find out.
- **Prove it forces something.** Switch the rule off in the reference rail and
  confirm the vector fails: `python3 scripts/forcing-gate.py --scope forced`. A
  vector that passes with or without the rule measures nothing. The baseline in
  `docs/FORCING-BASELINE.json` is a ratchet and CI replays it.

**A vector may not settle a question the specification leaves open.** If two
conformant verifiers could both be right, the vector belongs in
`vectors/indeterminate/`, which declares every reading a rail may take and holds a
rail to one of them coherently. Widening a reject vector's expected code set to
cover both readings does not work: the harness compares code sets, so a set naming
both conditions is satisfied by either answer and the vector stops measuring the
question instead of starting to.

## Adding a failure code

Four things, and `scripts/code-contract-gate.py` checks the last three:

- a condition the specification states that no existing code already names;
- a constant in `aee/codes.go`, in the block for the gate that detects it;
- the same spelling in the Python rail, so the two first-party rails share one
  vocabulary rather than two that happen to agree;
- at least one vector that emits it, which bumps `suiteRevision`.

A published code's spelling never changes and neither does the condition it names.
A changed condition is a new code.

## Bringing your own verifier

**This is the most valuable contribution available, and it does not require
touching this repository at all.** The suite counts implementations independent of
the specification's author, and today that count is one. Five rails written by one
person catch each other's transcription errors and cannot catch a misreading of
the specification, because they all inherit the same one. Two rules in this corpus
exist only because one outside reader read the text and reached a different answer.

The external contract is in [`README.md`](README.md): a verdict in the exit status,
a single-line JSON object on stdout carrying the codes and the recomputed result,
and a key policy read from `AEE_SUBSTRATE_KEYS` so both tier columns can be
compared. Evaluation order does not matter and message text does not matter.

```bash
python3 packaging/run_vectors.py --verifier "/path/to/your-verifier --json"
```

**If you intend the run to count as independent evidence, do not read
`vectors/interpretation-decisions.json`, the rail source, or the manifest's
expected condition codes first.** That registry is a reconciliation surface for
after you have committed to your own readings; read beforehand it is an answer key,
and an independence claim made against it is worth less than one made without it.
That rule is in this file because an outside implementer pointed out that nothing
said it.

Post a run with the source digest that produced it and it goes into
`docs/INDEPENDENT-RUNS.json` and into the independence column, transcribed exactly
as posted — never rounded, never restated as a fraction of a different corpus, and
never described as unprompted if you called it directed.

The reporting path is one form:
[`.github/ISSUE_TEMPLATE/independent-run.yml`](.github/ISSUE_TEMPLATE/independent-run.yml).
It asks for the corpus, the revision, the suite commit, the figures as you would
publish them, the label you give the run, and a link to a record that resolves.
Every posted run also gets a row in [`RUNS.md`](RUNS.md), in your own words.

**A run that disagreed with the corpus is worth more here than one that agreed**,
and nothing in the form asks you to have agreed. Two rules in this corpus exist
because an outside reader answered differently and was right.

## Adding a corpus of your own

A corpus against a different specification lands here as a sibling
`vectors-<name>/` directory, on the pattern `vectors-ai-agent-action/` already
sets, rather than as a new repository. The contract is in
[`.github/PULL_REQUEST_TEMPLATE/vectors-directory.md`](.github/PULL_REQUEST_TEMPLATE/vectors-directory.md):
a manifest with a derived digest, a generator that reproduces every byte, the
specification pinned by digest with a field saying whether those bytes are
upstream's or a proposal, and your name on the commits and in the manifest's
provenance.

Two items on that checklist are easy to miss and both fail in a stranger's hands
rather than in yours. The digest routine has to run for somebody who installed
nothing, so a generator that imports a third-party library moves its preimage
into a `digest.py` beside it that imports none; a release shipped without that
once, and the first command the README gives a reader died in a fresh clone. And
the corpus has to be registered in the places that enumerate corpora: the count
gate, the release digest list, the corpora table on the inbound page and the
corpus dropdown on the run form. Each of those refuses an unregistered corpus
rather than passing it over, which is the point.

Co-authorship is the normal shape for one of these, not an exception. Where the
whole distribution story lives, for a reader arriving from somewhere else, is
[`DISTRIBUTION.md`](DISTRIBUTION.md), and every run posted against any of these
corpora gets its row in [`RUNS.md`](RUNS.md).

## Raising an objection

Open an issue. State what you think is wrong and, if you can, what you think it
should be instead. Every objection from someone other than the maintainer becomes a
row in the disposition ledger under a permanent identifier, carrying your name, the
objection in your frame, the resolution and the reason — including when the
resolution is to decline it.

If you would rather your objection were recorded in your own words than in a
paraphrase, say so and it will be quoted verbatim; that is the default for
everything raised from now on.

## Commit messages

Plain ASCII, imperative subject under seventy-two characters, no AI-attribution
trailer, and no project-internal identifiers — audit numbers, decision-log
references, phase and round labels. Those resolve inside the document that minted
them and not in a history that outlives it. `.githooks/commit-msg --selftest` runs
the rule fixtures, and CI lints the range your push introduces from the same file.

## Licence

Contributions are accepted under the repository's licence,
[Apache-2.0](LICENSE), per section 5 of that licence. There is no separate
agreement to sign.
