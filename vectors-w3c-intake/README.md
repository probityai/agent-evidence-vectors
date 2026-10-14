# W3C intake-criteria conformance corpus

The conformance set for the intake criteria for a submitted conformance result
of the W3C public-agent-conformance community group: version 2 as posted on
2026-10-13 (list message `2026Oct/0067`), with the five wording deltas the
editor accepted the same day (`0070` deltas 1 to 4, `0075` delta 5) and the
field `0073` announced for the consolidated v2.1 text. The four messages are
vendored under `spec-vendored/` and pinned by sha256 in `MANIFEST.json`.

## Every ground is a sentence

The messages carry no identifiers. Each rejection ground is minted here as
`W3C-I-NNN` and bound to the exact sentence that fixed it: `gen_vectors.py`
finds the sentence in the vendored copy, records its line and hashes its bytes,
and a reword stops the build. `INDEX.md` lists all 45 grounds with criterion,
status (`v2`, `v2.1-delta`, `v2.1-announced`), sentence and digest, and every
member with the ground it is refused under. Criterion 13 carries no ground: the
criteria name no implementation, and these vectors are the shared test.

## The attack comes first

A member is one intake record. For every ground there is a record a careless
intake reader admits and that must be refused under that ground alone: a footer
total that proves itself, a selection silently bound to the first of three
matches, a relaxed control read as isolating because the state did not move, a
checker named by a branch, a native line transcribed clean. Every ground also
has a record that must be admitted, so a reader that refuses everything scores
zero. Members whose ground reads bytes on disk name a `root` under `trees/`, a
small fixture package with its output, anchor, checker source, lock file and
run-time helper.

## Run it

From a checkout (stdlib only, nothing to install):

```sh
export PYTHONPATH=packaging
python -m agent_evidence_vectors.w3cintake --judge vectors-w3c-intake
python -m agent_evidence_vectors.w3cintake --member vectors-w3c-intake/vectors/<id>.json
python -m agent_evidence_vectors.w3cintake record.json --root <dir the record's paths are under>
aee-verify vectors-w3c-intake
```

The record shape is ours and the rules are the group's; the module docstring of
`packaging/agent_evidence_vectors/w3cintake.py` says which field carries which
rule, and `docs/reference/w3c-intake.md` documents the record. Regenerate with
`python3 gen_vectors.py`; `--check` refuses a tree that differs.
