# The consumer policy document

Nine of the eleven rules the rego rail enforces are not facts about the statement. They
are facts about the deployment reading it: which corpus you expected, which substrate,
which coverage classes you require a run to have assessed, how old an observation may
be, and which result tokens you are willing to admit. None of those is in the statement,
none of them has a defensible default, and no amount of re-derivation inside the
predicate can supply one.

That is the whole reason this file exists. A policy that ships with safe-looking
defaults for those nine answers a question it was never told the answer to, and it
answers it in the admitting direction. So the rego rail takes them from a data document
mounted at `data.consumer`, and an unpinned deployment is DENIED rather than admitted.

```bash
cat > consumer-pins.json <<'JSON'
{"consumer": {
  "expected_corpus_digest":    "8b035678def9e5ac00ba761b8c640e4412c57163134afb9d2c1a90f49d573a52",
  "expected_substrate_digest": "<the substrate digest this deployment trusts>",
  "demanded_classes":          ["<the corpus classes a run must have assessed>"],
  "accepted_results":          ["pass"],
  "max_evidence_age_hours":    24
}}
JSON
opa eval -d rego/execution_evidence.rego -d consumer-pins.json \
  -I 'data.sigstore.isCompliant' < statement.json
```

## The eleven knobs

| key | absent means | what it decides |
|---|---|---|
| `expected_corpus_digest` | DENY, unless `allow_unpinned_anchors` | the corpus digest in `observationEnvironment` must equal this. Unpinned, the policy admits evidence about any corpus at all. |
| `expected_substrate_digest` | DENY, unless `allow_unpinned_anchors` | the substrate digest must equal this. Same argument, other axis. |
| `allow_unpinned_anchors` | the two anchors above are required | declines the specification's pinning requirement out loud. It excuses an ABSENT anchor only, never a mismatched one. |
| `demanded_classes` | DENY, unless `allow_unpinned_scope` | every class listed must appear in `coverage.assessedClasses`. |
| `allow_unpinned_scope` | `demanded_classes` is required | declines the scope demand out loud, with the same absent-only semantics. |
| `accepted_results` | the specification's own default token set | the result tokens this deployment admits. |
| `admit_unintercepted_clean_rows` | a clean row must be `basis: substrate` and `method: intercepted` | relaxes the clean-row provenance obligation. |
| `expected_catch_policy_digest` | the digest is bound but not compared | pins the catch policy the observation ran under. |
| `allowed_network_postures` | any posture in the closed vocabulary | restricts the egress postures this deployment will admit. |
| `max_issuance_lag_hours` | unbounded | bounds `issuedAt` minus `armedAt`. Needs no clock, so every rail can hold it. |
| `max_evidence_age_hours` | unbounded | bounds now minus `armedAt`. Needs a clock, so only some rails can hold it. |

## The scope pin is the one worth reading twice

A producer that withdraws a coverage class emits a statement byte-identical to one an
honest producer with no coverage emits. There is no field that separates them, because
the difference is an absence and an absence has no bytes. Your `demanded_classes` is
the only place the deciding fact exists.

This is the same shape as the indistinguishability problem the predicate's own text
addresses, arriving one layer up: a consumer that receives neither a positive
observation nor a recorded absence must refuse a workload rather than conclude
anything about it. A refusal of that kind has to be configured, because nothing in the
statement can trigger it.

## The offline reference verifier takes the same four, and takes them the same way

The offline verifier for this predicate exposes a `ConsumerPolicy` with
`substrateObservationKeys`, `expectedCorpusDigest`, `expectedSubstrateDigest`, and
`allowUnpinnedAnchors`. The last three are the same three knobs as the first three rows
above, with the same absent-input defaults and for the same reason, so a deployment
that pins an anchor for the offline verifier and forgets to pin it here has changed its
answer without meaning to.

Three differences are worth stating exactly, because parity is the natural assumption
and it does not hold:

- **`substrateObservationKeys` has no counterpart on any rail here.** The offline
  verifier checks each observation record's own signature against the keys you hand it,
  and derives `unattested` for every substrate row when you hand it none. No rail in
  this repository verifies a record signature; they check that a `signatures` array is
  present and non-empty, which is a structural check and not verification. That gap is
  the trust ceiling stated in `README.md`, and it is the single largest difference
  between reading a statement here and reading it offline.
- **The eight remaining knobs exist only here.** The offline verifier reaches its
  admission decision through validity plus tier policy plus the two anchors; the
  thresholds, the scope demand, the clean-row relaxation, and the two time bounds are
  admission-layer choices that a cluster makes and a replay does not.
- **sigstore policy-controller can mount no data document at all.** Its policy body is
  the policy, not a data document, so a deployment on that rail pins by replacing the
  right-hand side of the `expected_*` rules in `rego/execution_evidence.rego` with the
  literals it expects and regenerating the deployed `ClusterImagePolicy` manifest with
  `policy-controller/gen_soundness_cip.py`. The Kyverno rails pin by editing the
  placeholder literals their conditions carry, which is why an unedited Kyverno
  document denies every vector by construction and why the conformance harness lifts
  those conditions out of the corpus run rather than measuring the placeholder.

## A deployment that sets both opt-outs has a shape check

`allow_unpinned_anchors` and `allow_unpinned_scope` exist so that running unpinned is a
declared act rather than a silent default. Setting both and pinning nothing is
permitted, it is visible in the data document, and what it leaves is a policy that
checks the statement is well formed and internally consistent. That is worth something.
It is not an admission decision, and nothing here will pretend otherwise.
