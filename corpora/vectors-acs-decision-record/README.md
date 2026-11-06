# Control decision records

A policy decision point returns a verdict and keeps nothing. The [Agent Control
Specification](https://github.com/responsibleai/agent-control-spec) says so in its
README ("It applies no transform, resolves no approval and keeps no record") and makes
record keeping a host obligation; its section 19 says a host "MAY derive an audit
record" and its section 13.3 `evidence` is an opaque pointer the runtime does not
validate. This corpus defines the record and the checks a party who distrusts the host
runs on it.

A member is a DSSE envelope over an in-toto Statement v1 with predicate type
`https://probityai.github.io/agent-evidence-vectors/predicate/v1/control-decision`, plus
the artifacts the producer disclosed. The predicate binds three things:

| Member | What it binds |
| --- | --- |
| `input.digest` (and the subject digest) | SHA-256 of the RFC 8785 bytes of the agent-hooks context the decision point judged |
| `policy.manifestDigest`, `policy.bundleDigest` | SHA-256 of the manifest text, and of the RFC 8785 bytes of the Rego bundle |
| `verdict` | the verdict as the runtime returned it on the wire (`Verdict.to_wire`), approval block included |

## Running it

```sh
uv run --extra generators python corpora/vectors-acs-decision-record/gen_vectors.py
uv run --extra generators python corpora/vectors-acs-decision-record/check_vectors.py
cd corpora/vectors-acs-decision-record/run && uv run --locked python replay.py
```

The checker prints `control-decision: 15 members, 0 failures`. The replay evaluates every
member's disclosed manifest and bundle on its disclosed context with
`agent-control-spec==0.4.0a4` and prints `replay: 15 members, 0 unexpected mismatches`.

## The rules

The consumer supplies the producer key and the verdict it got by replaying the disclosed
bytes; neither is read from the record. The rules run in this order and the first that
fails is the code: `signature-invalid`, `statement-malformed`, `verdict-malformed`,
`policy-digest-missing`, `input-digest-mismatch`, `policy-digest-mismatch`,
`verdict-mismatch`. A record that passes all of them is accepted with `decision-bound`.
[INDEX.md](INDEX.md) lists the 4 accept and 11 reject members.

`reject-input-args-amount-lowered` is the case that motivates the input digest: the
disclosed payment amount was lowered after the decision, and replaying the edited
disclosure allows a payment the recorded run escalated. Only the digest catches it.

## Where the verdicts come from

`observedRuns` in [MANIFEST.json](MANIFEST.json) records one run of
`agent-control-spec==0.4.0a4` (environment `run/pyproject.toml` and `run/uv.lock`,
script `run/run_acs.py`, output `observed/run-acs-0.4.0a4.json` with its SHA-256). Every
accept member is that run's context, policy and verdict.

## What this does not establish

That the host evaluated the policy it recorded rather than another, that the action the
verdict allowed was carried out, or that the signing key belongs to anyone. The key here
is a published test key.
