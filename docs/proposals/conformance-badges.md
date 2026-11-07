# Conformance: the Verified by Probity badge, the status shield, and the board

Status: proposal, open for comments until 20 Nov 2026. Discussion: the conformance issue that links this page.

Several repositories already replay corpora from this repository in their own CI, and RUNS.md records five outside
runs. This page says how those runs become two public signals with different strength, and how one board shows them.

## Two signals, never confused

| Signal | What it rests on | Words used |
| --- | --- | --- |
| Badge | a grant under one of the two bases published in [VERIFIED-BADGE.md](../VERIFIED-BADGE.md), recorded in [badge-grants.json](../badge-grants.json) and re-checked at every release by `scripts/badge-grants-gate.py` | "Verified by Probity" |
| Status shield | a report the repository's own CI produced and the board fetched | `self-reported`, never "Verified" |

### The badge

The badge has two bases, both already published in VERIFIED-BADGE.md: applicant-originated conformance execution
through the released reusable workflow, and independent replay qualification, where a registered replay environment
this repository runs re-executes the implementation. The words, the bases and the grant ledger do not change here.
What this proposal adds is the release that makes the first basis usable.

Release 0.37.0 is planned to ship the reusable conformance workflow (pull request #477) in two jobs:

- an execution job that runs the candidate and holds no signing capability: no key, no `id-token: write`;
- a signer on a clean runner, with no candidate checkout, no shared writable workspace and no candidate-controlled
  cache. It uses pinned tooling, reads the candidate's output only as data, selects the artifact by repository, commit,
  workflow revision, run and attempt, and derives the expected case set from the pinned profile and corpus, never from
  the candidate's report.

The independent replay basis runs the same split in this repository: an implementation listed under
`implementations/<name>/` (a container image and an entrypoint that speaks the verifier contract) is executed by the
registered replay environment, and a passing record supports a grant with no further change in the implementer's
repository.

Each of these is release-blocking, with a test that must fail closed: a substituted artifact, an omitted mandatory
case, a forged success report, an unauthorized signing request, a fabricated passing report, a report from the wrong
repository or commit, an artifact whose digest differs from the logged line, a report with zero cases, and a replayed
stale run.

### The status shield

The shield is computed, never self-declared, and it reads, for example:

`self-reported · <profile>@<digest>: <passed>/<mandatory> mandatory passed · 3d ago`

It reads "incomplete" when coverage is short and "not evaluated" when no case applies. Age is counted from the time
the run executed. A later failing run supersedes an earlier pass at once, and a new corpus digest never inherits a
green result. The shield turns grey with "last passing run N days ago" once the newest passing run is more than 8
days old, so a weekly schedule has a day of slack; that reports on observation and says nothing about health.

A repository's CI can post its report as an uploaded workflow artifact, a committed file, a release asset or an
Evidence run issue. When it runs the Action, the Action's last step logs one line that locates and identifies the
measurement bundle:

`aev-report sha256=<digest> result=<pass|fail> executed=<n> vectors=<m> corpusDigest=<d> reference=<N>/<M> run=<repository>@<sha>#<runId>`

The line tells the board which bundle to fetch and what to recompute. It does not establish provenance by itself; a
repository owner who controls the runner controls the line, which is why the shield never says "Verified".

## Scoring: no aggregate threshold

A board POLICY.md, planned for 0.37.0, fixes how a figure is counted:

- every mandatory case of a profile passes, or the profile does not pass; there is no percentage tier;
- an expected rejection on a negative case is a pass;
- an expected-failure marker stays a failure in the count;
- a `disputed` case never leaves the denominator;
- a defective case leaves only through a reviewed, versioned entry in [DISPOSITIONS.md](../../DISPOSITIONS.md);
- zero applicable cases is "not evaluated", never a pass.

## Run labels

Every run row on the board and in RUNS.md carries two labels beside its figure:

- Mode A, reproduction (the run re-executed the implementation), or Mode B, recomputation (the run recomputed a
  verdict from records the implementation produced);
- author-produced or independent, relative to the implementation's author. A signature from this repository never
  makes a run independent.

The existing `blind` and `directed` labels in RUNS.md stay as the author's own word about how they implemented.

## The reference stage

The Action's reference stage today judges the adversarial execution evidence corpus and the done-receipt corpus; any
other corpus reads `0/M` there. Two changes are planned before the first outside badge:

- the stage moves to agent-evidence-verify and writes its verifier identifier, minted once and then frozen, into
  every report;
- per-corpus reference coverage appears on the shield, and the stage is extended to the corpora outside repositories
  replay most: receipt-signature, agent audit record, anchored chain and AI agent action.

## The board

The Agent Evidence Conformance Board is one generated `results.json` in this repository, rendered on this
repository's Pages site with the badge images, the status shields and a JSON feed. Every row carries the repository,
commit, run id, mode and authorship labels, and a correction history. A matrix of positive matches only, generated
from `main`, sits beside it.

## Dates

- 9 Nov: the reference stage pin moves and per-corpus coverage is published.
- 13 Nov: release 0.37.0 with the reusable workflow, the release-blocking tests, POLICY.md, the shield endpoint and
  `results.json`.
- 6 Dec: the target is at least three "Verified by Probity" grants under either basis.

Repositories already replaying a corpus appear as census rows on day one and as status shields once the board fetches
their first report. Pull requests that add the report step, a weekly schedule and an `implementations/<name>/` entry
go to those repositories from here.
