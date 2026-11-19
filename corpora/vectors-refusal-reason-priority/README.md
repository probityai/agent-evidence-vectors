# Refusal-reason-priority vectors

Cases for `refusal-reason-priority/v1`: one attestation response judged against the
refusal vocabulary of draft-li-rttp-iqa-addressing-02 (RTTP and IQA addressing).
Section 8.1 fixes five reason values and says the reason is the first value in the list
whose condition applies, so a refusal is auditable only when the emitted code is that
first one. The records were filed by the draft's author, ShaoBao Li (Lee) of Aicent
Stack, in issue 453 on this repository, from two families he publishes:
[aicent-grant-ref](https://github.com/Aicent-Stack/conformance/tree/main/candidates/aicent-grant-ref)
and
[aicent-lease-boundary](https://github.com/Aicent-Stack/conformance/tree/main/candidates/aicent-lease-boundary).

[![Checked with Probity](https://img.shields.io/badge/checked-with_Probity-blue?style=flat-square&logo=data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAMAAABEpIrGAAAAkFBMVEX8%2B%2Bzr5NPgyrfKyLnSq5Wzo4tWltqRkZI2kPU1kvk1j%2FMwkPgzjfI2jO80jO40jO3MdWOZc1SLblN1aFxxXFJzVDY2i%2B40i%2B00i%2Bw0i%2Bs0ius1iOZAapwugNYtdbUqaq0qV4tkRzJXOB47Oz43JRkjNEYiHBwlFxIfFxMcEg0XEQ0WEAwXDAUWCAEOCQcJAgCa503RAAAB3klEQVR42rWT2ZacIBCGceHYoN240SK2Crig4vL%2BbxfszJyZTmaSm6S4rI9a%2FwK3vxj41wDj5E9AwS%2Foxjn7DmARqgVHCBHyJcBxJeZtEG2Nv4hAGEPXYVumddvWAbFfgJJECDfDukxa63ldmw%2FiCTCEK%2BteFzNbQI%2BbQPwzwKJGjNO2LMacxNqK1wgcNfO2mqfbHMs8NEkeXT8AjurRTKfbMlqOa5vFyc8cZclu4PSvWptlPlOMeb4PsQu78MoYQWFIwKUet0nPZl%2FMki1H3x%2FKd1PVhhdkS2tDgM7m9bR3XX8EXtYde59SSVVXNx2NMwuIbbGl74HUu%2BcFXrArSpXqlVSpGz8sUG%2FjoCej1RHA6ZAgl1SmUvVUQjduEGDIdt0MxuwjCHYNAZSwT1IbhaZ%2BFt7BrUAXbguxnx3gZ9AJVJLal0hKaYv4OShGbu249Z4F4jhQ1PcpTUYLDBF5WxZB9dBB14O%2Bm6eu48QQpjBXIizf113iS9sF0LYxZMD1PODbVvtznu96sGOrWyFEiwQEwHNcC8gaF58UxfG1qiqMqzx2AACJ0i0qXyRXEIwjwnD1SBOYdKJ%2B7vxF1eRUaxGF9ePRVgiX3xxOccdhiK5v6v%2Fysgp2Z%2BR%2F3ebv9gP5RU8tSdZhDwAAAABJRU5ErkJggg%3D%3D)](https://github.com/probityai/probity)

For anyone who implements the vocabulary, or who writes a conformance check over refusal
reasons and wants one that scores the first applicable code, not any applicable one.

```sh
pip install agent-evidence-vectors
agent-evidence-vectors --corpus vectors-refusal-reason-priority
python3 corpora/vectors-refusal-reason-priority/check_vectors.py --verifier './verifier'
```

A verifier takes `record.json --json`, prints `{"decision": ..., "reason": ...}` and
exits 0 for `conformant`, 1 for `nonconformant` and 2 for `ambiguous`. In the GitHub
Action, set `corpus: vectors-refusal-reason-priority`.

## What the cases force

The reader applies ten checks in order and names the first that fails:
`contract_id_missing`, `contract_id_unknown`, `reason_member_absent`,
`reason_outside_closed_set` (a granted value, a sixth value), `answer_outside_both_boundary_readings`,
`refusal_without_condition` (no condition, no reason), `condition_ignored` (a permit over
stale evidence read through a diagnostic read), `later_value_emitted` (the priority),
`observation_backfilled` and `evidence_renewed_by_diagnostic_read`. Pairs share their facts
and differ in the code: a checker that accepts any applicable value fails exactly the later-code
member of each pair. Counts are in `MANIFEST.json`.

## Three questions the draft leaves open

At the lease instant, section 6.1 makes the boundary a declared convention. A permit under a
declared inclusive boundary and `evidence_expired` under a declared exclusive one are both
conformant, and frame acceptance in section 7.2 does not decide reliance. Three members are
`ambiguous` and list their readings: no boundary declared, and a declaration that contradicts the
answer in either direction. The author scores the contradiction nonconformant and discloses the
reading as strict, because the sentence asks for a declaration with SHOULD and states no
consequence. The corpus keeps his expected value in `authorExpected` and leaves the member open.

## Source and credit

Each member carries `source` (the family case id), `rule`, and the sentence of the draft it rests
on. Expected values are taken from the author only where they anchor to a published sentence.
`MANIFEST.json` pins the retrieved text of the draft at sha256
`02491c5a59d1e7471be04e8e0d4933dfc22ce19f9b054ead0aa449d6b4485044` and names the provenance as
`Aicent Stack, issue 453`. The families' sealed pages stay citations:
[aicent-grant-ref](https://iqa.org/conformance/aicent-grant-ref/) and
[aicent-lease-boundary](https://iqa.org/conformance/aicent-lease-boundary/). Members derived here
beyond the author's records say `derived from` and use the same sentences.

## Registration

- URI: `https://probityai.github.io/agent-evidence-vectors/predicate/v1/refusal-reason-priority`,
  defined here. This repository mints the records and owns the record shape below.
- Envelope: a bare JSON record, not an in-toto Statement: `contractId` (the URI), `recordId`,
  `facts` (what the answer was given over) and `response` (the `grantRef` with its lease instants,
  plus `reason`). The verdict is derivable from the record alone.
- Field semantics: the closed refusal set and its priority order are normative in
  draft-li-rttp-iqa-addressing-02, sections 6.1, 7.2, 8.1 and 8.2, owned by its author, Aicent-com.
- `confirmed_at`: Aicent-com confirmed revision 02 (retrieved text sha256
  `02491c5a59d1e7471be04e8e0d4933dfc22ce19f9b054ead0aa449d6b4485044`) on 7 Nov 2026, in
  [#492](https://github.com/probityai/agent-evidence-vectors/issues/492#issuecomment-6710136659).
- Example: `cases/conformant-expiry-over-revocation/record.json` (record sha256
  `8fdf1041bc8b0e8dd9c2b47f03649fc7a0f3b313fda633061af309492e5df54f`, source case GR-P03).
- Compatibility: v1 never changes. A value outside the closed set, or a change to the set or the
  order, is a new URI beside v1. A later draft revision that keeps the set, the order and the field
  meanings is recorded as a new confirmation here, never as an edit of this one.

## What it does not test

Value formats, identifier syntax, and whether an implementation finds the boundary instant from
the observation time and lease expiry; the facts are given. Every member is synthetic. Regenerate
with `python3 corpora/vectors-refusal-reason-priority/gen_vectors.py`.
