# Vendored predicate specification

[`predicates/adversarial-execution-evidence.md`](predicates/adversarial-execution-evidence.md)
is a version-locked copy of the Adversarial Execution Evidence predicate
specification, vendored so this repository is self-contained: a relying party
can implement or check the predicate from this repo alone, and the `spec:NNN`
line references throughout the Go and Python source resolve against a file that
is actually present here (they cite line numbers in this copy).

- **Tracks:** the upstream repository, pull request and commit these bytes were
  taken from are recorded in [`VENDOR-PIN.json`](VENDOR-PIN.json), together with
  their SHA-256. That file is written by
  [`scripts/vendor-spec.py`](../scripts/vendor-spec.py) from git at vendor time
  and is not maintained by hand.
- **Version:** v0.7.0 (`https://in-toto.io/attestation/adversarial-execution-evidence/v0.7`).
- **The type URI does not resolve.** The in-toto attestation catalog redirects
  the URIs of vetted predicates whose specification is merged, and this
  predicate is in review as `in-toto/attestation#570`, so a request for the URI
  returns 404. That is the ordinary condition of a predicate at that stage: the
  URI identifies the predicate type, and dereferencing it is not what makes a
  statement conformant. Read the specification in the copy beside this file, at
  [`predicates/adversarial-execution-evidence.md`](predicates/adversarial-execution-evidence.md).
  The same holds for the `$id` in
  [`witnessattestor/schema/aee-v0.7.schema.json`](../witnessattestor/schema/aee-v0.7.schema.json).
- **Authority:** the canonical namespace is the in-toto attestation catalog.
  This repository is the reference implementation and conformance authority for
  that predicate, not a competing source of truth. On any normative change
  upstream, this copy is re-vendored at the new pinned commit and the corpus is
  regenerated with a `suiteRevision` bump.

The copy is byte-verbatim (no added header) precisely so the line numbers the
source cites stay accurate.

The pin used to be a commit hash written into this paragraph by hand, and it
went stale the first time the upstream branch moved: it named a commit three
normative revisions behind the bytes beside it. That is worth more than a
typo's attention, because an implementer working from this repository diffs the
vendored copy against the pinned commit to certify there is no version skew,
and a pin naming the wrong commit either reports a drift that does not exist or
conceals one that does. `spec-drift-gate.py` now fails closed unless the
vendored bytes, the pin, and the digest the corpus was generated against all
agree.

## Long-form specification material

The registry entry in the in-toto catalog is sized to that registry: type URI,
schema, parsing rules, one line per field, examples, changelog. The material the
specification argues rather than states -- the recompute split, each encoding
rule with the divergence it closes, the eleven coverage validity requirements
and where each stops, the consumer policy obligations, and the per-version
history -- lives beside it in
[`predicates/adversarial-execution-evidence/`](predicates/adversarial-execution-evidence/),
verbatim from the single-document revision. That directory is what the registry
page links to, and its README says which file holds what.

It is not a second source of truth. Where a companion and the registry page
differ on a normative rule, the page governs and the difference is a defect to
report.
