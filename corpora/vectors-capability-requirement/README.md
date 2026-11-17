# Capability-requirement vectors

Cases for `capability-requirement/v1`: what a customer holds when the model behind a product is a hosted endpoint and no bytes can be hashed. Digests of a swap record a swap after it happens. This corpus tests the part that has to exist before any swap, and what a verifier may say about a hosted endpoint afterwards. The expected decision and reason for every case are in `MANIFEST.json`.

[![Checked with Probity](https://img.shields.io/badge/checked-with_Probity-blue?style=flat-square&logo=data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAMAAABEpIrGAAAAkFBMVEX8%2B%2Bzr5NPgyrfKyLnSq5Wzo4tWltqRkZI2kPU1kvk1j%2FMwkPgzjfI2jO80jO40jO3MdWOZc1SLblN1aFxxXFJzVDY2i%2B40i%2B00i%2Bw0i%2Bs0ius1iOZAapwugNYtdbUqaq0qV4tkRzJXOB47Oz43JRkjNEYiHBwlFxIfFxMcEg0XEQ0WEAwXDAUWCAEOCQcJAgCa503RAAAB3klEQVR42rWT2ZacIBCGceHYoN240SK2Crig4vL%2BbxfszJyZTmaSm6S4rI9a%2FwK3vxj41wDj5E9AwS%2Foxjn7DmARqgVHCBHyJcBxJeZtEG2Nv4hAGEPXYVumddvWAbFfgJJECDfDukxa63ldmw%2FiCTCEK%2BteFzNbQI%2BbQPwzwKJGjNO2LMacxNqK1wgcNfO2mqfbHMs8NEkeXT8AjurRTKfbMlqOa5vFyc8cZclu4PSvWptlPlOMeb4PsQu78MoYQWFIwKUet0nPZl%2FMki1H3x%2FKd1PVhhdkS2tDgM7m9bR3XX8EXtYde59SSVVXNx2NMwuIbbGl74HUu%2BcFXrArSpXqlVSpGz8sUG%2FjoCej1RHA6ZAgl1SmUvVUQjduEGDIdt0MxuwjCHYNAZSwT1IbhaZ%2BFt7BrUAXbguxnx3gZ9AJVJLal0hKaYv4OShGbu249Z4F4jhQ1PcpTUYLDBF5WxZB9dBB14O%2Bm6eu48QQpjBXIizf113iS9sF0LYxZMD1PODbVvtznu96sGOrWyFEiwQEwHNcC8gaF58UxfG1qiqMqzx2AACJ0i0qXyRXEIwjwnD1SBOYdKJ%2B7vxF1eRUaxGF9ePRVgiX3xxOccdhiK5v6v%2Fysgp2Z%2BR%2F3ebv9gP5RU8tSdZhDwAAAABJRU5ErkJggg%3D%3D)](https://github.com/probityai/probity)

## The three records

| Kind | What it carries |
| --- | --- |
| `requirement` | The capability, stated apart from any model (an id and a statement, nothing else). The pass thresholds, one per metric, each with a comparator, an integer value and a drift tolerance. The evaluation set by the digest of its item digests, and a held-out part the assessor keeps, named by a commitment and the assessor's key. The requirer signs the requirement; the assessor attests the commitment. |
| `endpoint-report` | The requirement, the endpoint, one signed run, and two findings stated as two members: `modelIdentity` and `behaviour`. |
| `drift` | The requirement, a baseline run, a current run, and their comparison. |

A run is signed by the verifier. Its held-out results carry a second signature, the assessor's, over the results with the run id and the requirement digest, so a signature from another run or another key does not count.

## Two findings, never one verdict

For a hosted endpoint the report says `modelIdentity: unproven`, because no weights are held. It says `behaviour` separately: `supported`, `contradicted` or `not_established` on the pinned set. A report with a single pass or fail member is refused, and so is one that reads good behaviour as the identity of the model. `modelIdentity` may be `proven` only when the endpoint holds weights and the report carries the digest of them, equal to the digest claimed.

Behaviour is `contradicted` when any usable value misses its threshold, else `not_established` when a threshold has no usable value, else `supported`. A held-out value is usable only with the named assessor's signature for that run. A held-out part that is absent leaves behaviour not established; it never supports.

## Drift is two signed runs compared

Both runs name the digest of one requirement and one endpoint. The comparison is recomputed from the runs: `drifted` when a metric worsened by more than its tolerance or fell from meeting its threshold to missing it, else `not_established` when a metric has no usable value in both runs, else `stable`. One run listed twice, two runs sharing an id, and a current run no later than the baseline are refused.

## Checks, in order

The reader names the first check that fails. `contract_id_missing`, `contract_id_unknown`, `kind_unknown`, `requirement_signature_invalid`, `capability_names_a_model`, `thresholds_invalid`, `evaluation_set_digest_mismatch`, `held_out_commitment_not_attested`, `requirement_invalid`, `run_against_other_requirement`, `runs_on_different_endpoints`, `run_signature_invalid`, `held_out_not_assessor_signed`, `findings_merged`, `model_identity_overclaimed`, `behaviour_mismatch`, `runs_not_distinct`, `runs_out_of_order`, `comparison_wrong`. A check that does not apply to a record's kind passes. A record that passes every check is `allow` with reason `record_consistent`; a report that honestly says contradicted is `allow`, because the record is consistent.

The `allow-` cases are controls: the word model inside a statement, a threshold met exactly, a held-out part not run, a public miss that contradicts without a held-out part, an improvement that is not drift, and a flip across a threshold inside the tolerance that is.

## Run it

```sh
agent-evidence-vectors --corpus vectors-capability-requirement
python3 corpora/vectors-capability-requirement/check_vectors.py --verifier "<verifier>"
```

The external-verifier contract is `<verifier> <case-dir>/record.json --json`, printing `decision` and `reason`, exit 0 for allow and 1 for deny.

## What a pass means

The cases check that signatures verify against the keys a record names, and that the record's findings follow from what it holds. Which keys a deployment trusts is a separate decision and is not tested. The corpus tests measure a verifier that checks only signatures and one that trusts held-out values whoever signed them; each passes every control and misses cases. All members are synthetic, and the keys are test keys published on purpose.
