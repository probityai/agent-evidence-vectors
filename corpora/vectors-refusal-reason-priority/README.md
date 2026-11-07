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
beyond the author's records say `derived from` and use the same sentences. The draft is
Informational and can change; a later revision overrides this reading.

## What it does not test

Value formats, identifier syntax, and whether an implementation finds the boundary instant from
the observation time and lease expiry; the facts are given. Every member is synthetic. Regenerate
with `python3 corpora/vectors-refusal-reason-priority/gen_vectors.py`.
