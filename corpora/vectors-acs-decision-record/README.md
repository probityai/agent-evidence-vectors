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

[![Checked with Probity](https://img.shields.io/badge/checked-with_Probity-blue?style=flat-square&logo=data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAMAAABEpIrGAAAAkFBMVEX8%2B%2Bzr5NPgyrfKyLnSq5Wzo4tWltqRkZI2kPU1kvk1j%2FMwkPgzjfI2jO80jO40jO3MdWOZc1SLblN1aFxxXFJzVDY2i%2B40i%2B00i%2Bw0i%2Bs0ius1iOZAapwugNYtdbUqaq0qV4tkRzJXOB47Oz43JRkjNEYiHBwlFxIfFxMcEg0XEQ0WEAwXDAUWCAEOCQcJAgCa503RAAAB3klEQVR42rWT2ZacIBCGceHYoN240SK2Crig4vL%2BbxfszJyZTmaSm6S4rI9a%2FwK3vxj41wDj5E9AwS%2Foxjn7DmARqgVHCBHyJcBxJeZtEG2Nv4hAGEPXYVumddvWAbFfgJJECDfDukxa63ldmw%2FiCTCEK%2BteFzNbQI%2BbQPwzwKJGjNO2LMacxNqK1wgcNfO2mqfbHMs8NEkeXT8AjurRTKfbMlqOa5vFyc8cZclu4PSvWptlPlOMeb4PsQu78MoYQWFIwKUet0nPZl%2FMki1H3x%2FKd1PVhhdkS2tDgM7m9bR3XX8EXtYde59SSVVXNx2NMwuIbbGl74HUu%2BcFXrArSpXqlVSpGz8sUG%2FjoCej1RHA6ZAgl1SmUvVUQjduEGDIdt0MxuwjCHYNAZSwT1IbhaZ%2BFt7BrUAXbguxnx3gZ9AJVJLal0hKaYv4OShGbu249Z4F4jhQ1PcpTUYLDBF5WxZB9dBB14O%2Bm6eu48QQpjBXIizf113iS9sF0LYxZMD1PODbVvtznu96sGOrWyFEiwQEwHNcC8gaF58UxfG1qiqMqzx2AACJ0i0qXyRXEIwjwnD1SBOYdKJ%2B7vxF1eRUaxGF9ePRVgiX3xxOccdhiK5v6v%2Fysgp2Z%2BR%2F3ebv9gP5RU8tSdZhDwAAAABJRU5ErkJggg%3D%3D)](https://github.com/probityai/probity)

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
