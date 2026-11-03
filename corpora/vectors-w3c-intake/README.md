# W3C intake-criteria conformance corpus

The conformance set for the intake criteria for a submitted conformance result
of the W3C public-agent-conformance community group: version 2 as posted on
2026-10-13 (list message `2026Oct/0067`), with the five wording deltas the
editor accepted the same day (`0070` deltas 1 to 4, `0075` delta 5) and the
field `0073` announced for the consolidated v2.1 text, plus the criterion-6
consumed state Lars Kersten Kroehl proposed in `0090` and Nicolas Rocchia
measured in `0091` (a file can be pinned, listed and carried and still enter no
verdict). The six messages are vendored under `spec-vendored/` and pinned by
sha256 in `MANIFEST.json`.

[![Checked with Probity](https://img.shields.io/badge/checked-with_Probity-0969da?logo=data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAMAAABEpIrGAAAAkFBMVEX8%2B%2Bzr5NPgyrfKyLnSq5Wzo4tWltqRkZI2kPU1kvk1j%2FMwkPgzjfI2jO80jO40jO3MdWOZc1SLblN1aFxxXFJzVDY2i%2B40i%2B00i%2Bw0i%2Bs0ius1iOZAapwugNYtdbUqaq0qV4tkRzJXOB47Oz43JRkjNEYiHBwlFxIfFxMcEg0XEQ0WEAwXDAUWCAEOCQcJAgCa503RAAAB3klEQVR42rWT2ZacIBCGceHYoN240SK2Crig4vL%2BbxfszJyZTmaSm6S4rI9a%2FwK3vxj41wDj5E9AwS%2Foxjn7DmARqgVHCBHyJcBxJeZtEG2Nv4hAGEPXYVumddvWAbFfgJJECDfDukxa63ldmw%2FiCTCEK%2BteFzNbQI%2BbQPwzwKJGjNO2LMacxNqK1wgcNfO2mqfbHMs8NEkeXT8AjurRTKfbMlqOa5vFyc8cZclu4PSvWptlPlOMeb4PsQu78MoYQWFIwKUet0nPZl%2FMki1H3x%2FKd1PVhhdkS2tDgM7m9bR3XX8EXtYde59SSVVXNx2NMwuIbbGl74HUu%2BcFXrArSpXqlVSpGz8sUG%2FjoCej1RHA6ZAgl1SmUvVUQjduEGDIdt0MxuwjCHYNAZSwT1IbhaZ%2BFt7BrUAXbguxnx3gZ9AJVJLal0hKaYv4OShGbu249Z4F4jhQ1PcpTUYLDBF5WxZB9dBB14O%2Bm6eu48QQpjBXIizf113iS9sF0LYxZMD1PODbVvtznu96sGOrWyFEiwQEwHNcC8gaF58UxfG1qiqMqzx2AACJ0i0qXyRXEIwjwnD1SBOYdKJ%2B7vxF1eRUaxGF9ePRVgiX3xxOccdhiK5v6v%2Fysgp2Z%2BR%2F3ebv9gP5RU8tSdZhDwAAAABJRU5ErkJggg%3D%3D)](https://github.com/probityai/probity)

## Every ground is a sentence

The messages carry no identifiers. Each rejection ground is minted here as
`W3C-I-NNN` and bound to the exact sentence that fixed it: `gen_vectors.py`
finds the sentence in the vendored copy, records its line and hashes its bytes,
and a reword stops the build. `INDEX.md` lists all 48 grounds with criterion,
status (`v2`, `v2.1-delta`, `v2.1-announced`, `v2.1-proposed`), sentence and
digest, and every
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
run-time helper. The anchor is a digest list signed with a fixture Ed25519 key
derived from a fixed label in `gen_vectors.py`; it signs nothing else. Three
members re-pin a consistent rewrite (a member edited, a member deleted, the list
re-signed under another key) and must be refused under W3C-I-024, because the
signature no longer verifies under the pinned key even though every digest
agrees.

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
