# Tool-descriptor-digest vectors

Cases for `tool-descriptor-digest/v1`: one pin and one observation of an MCP tool
descriptor, each a profile, a digest and the descriptor the digest was computed from.
Public digests of the same descriptor do not agree on the fields they cover (title and
annotations in or out), on an absent member (omitted or the empty string), or on the
canonical bytes, so two honest producers can disagree about a descriptor that never changed.
The rule here is the one OWASP Agentic-Evidence
[issue 4](https://github.com/OWASP/Agentic-Evidence/issues/4) states and its maintainers took
into triage: a pin and an observation compare only when both carry a profile and the two
profiles are equal; where they differ the result is a gap, not a contradiction.

[![Checked with Probity](https://img.shields.io/badge/checked-with_Probity-blue?style=flat-square&logo=data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAMAAABEpIrGAAAAkFBMVEX8%2B%2Bzr5NPgyrfKyLnSq5Wzo4tWltqRkZI2kPU1kvk1j%2FMwkPgzjfI2jO80jO40jO3MdWOZc1SLblN1aFxxXFJzVDY2i%2B40i%2B00i%2Bw0i%2Bs0ius1iOZAapwugNYtdbUqaq0qV4tkRzJXOB47Oz43JRkjNEYiHBwlFxIfFxMcEg0XEQ0WEAwXDAUWCAEOCQcJAgCa503RAAAB3klEQVR42rWT2ZacIBCGceHYoN240SK2Crig4vL%2BbxfszJyZTmaSm6S4rI9a%2FwK3vxj41wDj5E9AwS%2Foxjn7DmARqgVHCBHyJcBxJeZtEG2Nv4hAGEPXYVumddvWAbFfgJJECDfDukxa63ldmw%2FiCTCEK%2BteFzNbQI%2BbQPwzwKJGjNO2LMacxNqK1wgcNfO2mqfbHMs8NEkeXT8AjurRTKfbMlqOa5vFyc8cZclu4PSvWptlPlOMeb4PsQu78MoYQWFIwKUet0nPZl%2FMki1H3x%2FKd1PVhhdkS2tDgM7m9bR3XX8EXtYde59SSVVXNx2NMwuIbbGl74HUu%2BcFXrArSpXqlVSpGz8sUG%2FjoCej1RHA6ZAgl1SmUvVUQjduEGDIdt0MxuwjCHYNAZSwT1IbhaZ%2BFt7BrUAXbguxnx3gZ9AJVJLal0hKaYv4OShGbu249Z4F4jhQ1PcpTUYLDBF5WxZB9dBB14O%2Bm6eu48QQpjBXIizf113iS9sF0LYxZMD1PODbVvtznu96sGOrWyFEiwQEwHNcC8gaF58UxfG1qiqMqzx2AACJ0i0qXyRXEIwjwnD1SBOYdKJ%2B7vxF1eRUaxGF9ePRVgiX3xxOccdhiK5v6v%2Fysgp2Z%2BR%2F3ebv9gP5RU8tSdZhDwAAAABJRU5ErkJggg%3D%3D)](https://github.com/probityai/probity)

For anyone who pins a tool descriptor and checks it later, or who maps descriptor evidence
between two projects, and wants a check that refuses to call an incomparable pair contradicted.

```sh
pip install agent-evidence-vectors
agent-evidence-vectors --corpus vectors-tool-descriptor-digest
python3 corpora/vectors-tool-descriptor-digest/check_vectors.py --verifier './verifier'
```

A verifier takes `record.json --json`, prints `{"decision": ..., "reason": ...}` and exits 0
for `match`, 1 for `contradicted`, 2 for `gap` and 3 for `refused`. In the GitHub Action, set
`corpus: vectors-tool-descriptor-digest`.

## The three profiles

A digest is `sha256-` and the base64 of the SHA-256 of the RFC 8785 bytes of the covered members.

| Profile | Covers | Absent member |
| --- | --- | --- |
| `name-description-inputschema.omit-absent.jcs` | name, description, inputSchema | omitted |
| `name-description-inputschema-outputschema.empty-description.jcs` | those and outputSchema | description becomes the empty string |
| `whole-descriptor.omit-absent.jcs` | every member except `_meta` | omitted |

## What the cases force

The reader checks in order and names the first that fails: `contract_id_missing`,
`contract_id_unknown`, `profile_unknown`, `descriptor_not_canonicalizable` (the suite admits
integers, strings, booleans, null, arrays and objects) and `digest_not_recomputed` (the stated
digest is not what the descriptor gives under the stated profile). A record that passes is then
compared. Equal profiles with different digests are `contradicted`. A profile missing on
either side, or two profiles that differ, is a `gap`, including when the two digest strings
happen to be equal. Equal profiles with equal digests are a `match`, including when a member the
profile does not cover changed. One member carries property keys on both sides of the UTF-16
surrogate range, which RFC 8785 sorts opposite to code point order.

Two members come from one recorded change in a published dataset of MCP tool-list changes
(Zenodo 10.5281/zenodo.23512760, change 5206, a server's tool list observed on 2026-09-28): one
tool whose description was rewritten, and the unchanged tool beside it. The change rewrote the
description of four of the five tools in the list. `source/histor-change-5206.json` holds both
tool lists exactly as the dataset serves them, and the generator checks that each list
reproduces its recorded set digest (SHA-256 of the RFC 8785 bytes of the tool list) before it
builds a member from it.

Counts are in `MANIFEST.json`.
