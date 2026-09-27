# Documentation

The [README](../README.md) is the short version. These pages carry the detail.

| page | what it covers |
| --- | --- |
| [Running the suite](RUNNING.md) | the GitHub Action, the `agent-evidence-vectors` command, its inputs and outputs, what a conformance claim must show, and judging every corpus with `aee-verify` |
| [The corpora](CORPORA.md) | what each corpus tests, the predicate and release version axes, and the specification-reference gates |
| [The verifier contract](VERIFIER-CONTRACT.md) | failure codes, what the harness compares, `statementLayer`, the code registry, indeterminate vectors, condition ids |
| [What the corpus forces](FORCING.md) | the forcing measurement, its limits, detector liveness, and the accept anchor beside every refusal |
| [Verify a release and cite it](VERIFY-A-RELEASE.md) | the four-command release check and the citation |
| [Architecture](ARCHITECTURE.md) | repository layout, the verification pipeline, the go-witness attestor |
| [Adoption and independent runs](ADOPTION.md) | who uses the suite, and every run by an implementation this repository did not write |

## How this suite is maintained

A conformance suite is only useful to a party who trusts neither the producer nor
the implementer, and such a party cannot weigh a set of bytes without knowing how
the bytes are maintained. Three files answer that without anyone having to be
asked:

- [`GOVERNANCE.md`](../GOVERNANCE.md) — who decides, what the maintainer explicitly
  does not decide, what is never changed at any revision, how a revision is cut,
  and the one property a citing document should treat as unmet;
- [`CONTRIBUTING.md`](../CONTRIBUTING.md) — where a proposal goes, the single command
  that runs every gate locally, and what each gate refuses;
- [`DISPOSITIONS.md`](../DISPOSITIONS.md) — every objection received from someone
  other than the maintainer, in the objector's own frame, with the resolution and
  the reason. Including the ones that were declined, which are the rows worth
  reading first.

## Arriving from somewhere else

Two files carry what a reader who did not come from here needs, and neither one
of them is a summary of this page.

- [`DISTRIBUTION.md`](../DISTRIBUTION.md) is the inbound page: the tag to cite, the
  module path, the release-verification recipe above, how to cite a corpus so
  the citation still resolves to the same bytes next year, and what a sibling
  `vectors-*` directory of your own has to carry. It is deliberately inbound
  only and records nothing about where this suite has been sent.
- [`RUNS.md`](../RUNS.md) is the scoreboard for runs by implementations this
  repository did not write: one row per posted run, in the reporter's own words,
  under the label its own author gave it, with blind and directed kept apart
  rather than added together. The form at
  [`.github/ISSUE_TEMPLATE/independent-run.yml`](../.github/ISSUE_TEMPLATE/independent-run.yml)
  is the whole reporting path, and a run that disagreed with the corpus is the
  row worth having.

`scripts/distribution-gate.py` holds the inbound page to this repository: the
recipe there is byte-identical to the one above, every tag it names is the one
`CITATION.cff` calls released, and its corpora table and that form both hold
exactly the tracked corpus set.
