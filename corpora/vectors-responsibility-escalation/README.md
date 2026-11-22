# Responsibility-escalation vectors

Cases for `responsibility-escalation/v1`: one synthetic record of a hiring agent's decision and
its escalation to a designated human role, and what a receiver can establish from it. The nine
cases restate the matrix on the W3C public-agent-identity list, October 2026 (messages 2026Oct
0035 and 0043): the first eight are authority and escalation failures, the ninth is the clean path
closed on time. The outcome tokens are this corpus's proposal; the list gives expected outcomes for
the failure states and leaves success in prose.

[![Checked with Probity](https://img.shields.io/badge/checked-with_Probity-blue?style=flat-square&logo=data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAMAAABEpIrGAAAAkFBMVEX8%2B%2Bzr5NPgyrfKyLnSq5Wzo4tWltqRkZI2kPU1kvk1j%2FMwkPgzjfI2jO80jO40jO3MdWOZc1SLblN1aFxxXFJzVDY2i%2B40i%2B00i%2Bw0i%2Bs0ius1iOZAapwugNYtdbUqaq0qV4tkRzJXOB47Oz43JRkjNEYiHBwlFxIfFxMcEg0XEQ0WEAwXDAUWCAEOCQcJAgCa503RAAAB3klEQVR42rWT2ZacIBCGceHYoN240SK2Crig4vL%2BbxfszJyZTmaSm6S4rI9a%2FwK3vxj41wDj5E9AwS%2Foxjn7DmARqgVHCBHyJcBxJeZtEG2Nv4hAGEPXYVumddvWAbFfgJJECDfDukxa63ldmw%2FiCTCEK%2BteFzNbQI%2BbQPwzwKJGjNO2LMacxNqK1wgcNfO2mqfbHMs8NEkeXT8AjurRTKfbMlqOa5vFyc8cZclu4PSvWptlPlOMeb4PsQu78MoYQWFIwKUet0nPZl%2FMki1H3x%2FKd1PVhhdkS2tDgM7m9bR3XX8EXtYde59SSVVXNx2NMwuIbbGl74HUu%2BcFXrArSpXqlVSpGz8sUG%2FjoCej1RHA6ZAgl1SmUvVUQjduEGDIdt0MxuwjCHYNAZSwT1IbhaZ%2BFt7BrUAXbguxnx3gZ9AJVJLal0hKaYv4OShGbu249Z4F4jhQ1PcpTUYLDBF5WxZB9dBB14O%2Bm6eu48QQpjBXIizf113iS9sF0LYxZMD1PODbVvtznu96sGOrWyFEiwQEwHNcC8gaF58UxfG1qiqMqzx2AACJ0i0qXyRXEIwjwnD1SBOYdKJ%2B7vxF1eRUaxGF9ePRVgiX3xxOccdhiK5v6v%2Fysgp2Z%2BR%2F3ebv9gP5RU8tSdZhDwAAAABJRU5ErkJggg%3D%3D)](https://github.com/probityai/probity)

For anyone who writes a receiver for historical authority and human-escalation evidence and wants
a bounded test that scores what the record establishes, never what it implies.

```sh
pip install agent-evidence-vectors
agent-evidence-vectors --corpus vectors-responsibility-escalation
python3 corpora/vectors-responsibility-escalation/check_vectors.py --verifier './verifier'
```

A verifier takes `record.json --json`, prints `{"decision": ..., "reason": ...}` and exits 0 for
`established`, 1 for `not_established`, 2 for `partial` and 3 for `unresolved`. In the GitHub
Action, set `corpus: vectors-responsibility-escalation`.

## The nine cases

| # | Case | Decision class | Outcome |
| --- | --- | --- | --- |
| 1 | `h01-authority-narrowed-after-decision` | screen out a candidate | established / authority_held_at_decision_time |
| 2 | `h02-referral-without-receipt` | adverse background determination | partial / receipt_not_evidenced |
| 3 | `h03-acknowledged-without-acceptance` | request sensitive documents | partial / acceptance_not_evidenced |
| 4 | `h04-unanswered-escalation` | screen out a candidate | unresolved / escalation_unanswered |
| 5 | `h05-reference-unavailable` | adverse background determination | not_established / reference_unavailable |
| 6 | `h06-authority-narrowed-before-acknowledgement` | request sensitive documents | partial / authority_narrowed_before_acknowledgement |
| 7 | `h07-current-record-resolved` | screen out a candidate | not_established / current_record_resolved_not_decision_time |
| 8 | `h08-acknowledged-outside-role` | adverse background determination | partial / acknowledged_outside_designated_role |
| 9 | `h09-clean-path-closed-on-time` | screen out a candidate | established / closed_as_accepted |

Each case is the clean record of case 9 with the change that names it. The first eight end at
acceptance, because the first matrix stops there, so they carry no closure slot; case 9 requires
closure by the designated role inside its window. Each record states the instant the authority is
read at (the decision instant, or the referral instant in case 6) and the instant the receiver
evaluates at. The three decision classes are the ones the list names as closed by a human role;
the assignment of a class to each case is this corpus's.

## What the reader checks

Seventeen checks in a fixed order, and the first that fails names the reason:
`contract_id_missing`, `contract_id_unknown`, `referral_not_evidenced`,
`event_after_evaluation_instant`, `reference_unavailable`, `reference_inconsistent`,
`current_record_resolved_not_decision_time`, `authority_not_held_at_read_instant`,
`receipt_not_evidenced`, `escalation_unanswered`, `acknowledged_outside_designated_role`,
`authority_narrowed_before_acknowledgement`, `acceptance_not_evidenced`,
`accepted_outside_designated_role`, `closure_not_evidenced`, `closed_outside_designated_role` and
`closed_late`. Seven are named by a case. The other ten are forced by one change to the clean
record in `tests/test_corpus.py`, so a receiver that skips any of them is caught. A late closure
is its own state, `partial / closed_late`: closed, with the lateness visible, and neither a clean
pass nor unresolved. A slot with no evidence counts as no evidence whatever the observation
coverage, so later slots never repair a missing earlier one.

## Receiver run

Run 20 Nov 2026 with `agent-evidence-verify`, the version `pyproject.toml` pins for its
cross-check (0.5.0) and the current release on PyPI (0.6.0): both compare 46 verdicts and agree on
all 46 (`crosscheck_probity_verify.py`, `uv run --group crosscheck python
corpora/vectors-responsibility-escalation/crosscheck_probity_verify.py
corpora/vectors-responsibility-escalation`). The verifier answers two questions per case, and the
table gives its verdict for each. The authority is `authority_anchor/v1` over a capture of what the
reference resolved to, pinned to the version in force at the read instant and its standing. Each
slot is `event_absence/v1` over an observation and a capabilities record: an evidenced slot reads
`contradicted / event_observed` for the claim that it is empty, an unevidenced slot over complete
coverage reads `supported / absence_within_covered_scope`.

| # | Case | This corpus | Authority | Slots (the verifier's reading) |
| --- | --- | --- | --- | --- |
| 1 | `h01-authority-narrowed-after-decision` | established / authority_held_at_decision_time | supported / anchor_matches | referral, receipt, acknowledgement, acceptance observed |
| 2 | `h02-referral-without-receipt` | partial / receipt_not_evidenced | supported / anchor_matches | referral observed; receipt, acknowledgement, acceptance absent |
| 3 | `h03-acknowledged-without-acceptance` | partial / acceptance_not_evidenced | supported / anchor_matches | referral, receipt, acknowledgement observed; acceptance absent |
| 4 | `h04-unanswered-escalation` | unresolved / escalation_unanswered | supported / anchor_matches | referral, receipt observed; acknowledgement, acceptance absent |
| 5 | `h05-reference-unavailable` | not_established / reference_unavailable | not_established / authority_response_unavailable | referral, receipt, acknowledgement, acceptance observed |
| 6 | `h06-authority-narrowed-before-acknowledgement` | partial / authority_narrowed_before_acknowledgement | supported / anchor_matches | referral, receipt, acknowledgement, acceptance observed |
| 7 | `h07-current-record-resolved` | not_established / current_record_resolved_not_decision_time | contradicted / anchor_mismatch | referral, receipt, acknowledgement, acceptance observed |
| 8 | `h08-acknowledged-outside-role` | partial / acknowledged_outside_designated_role | supported / anchor_matches | referral, receipt, acknowledgement observed; acceptance absent |
| 9 | `h09-clean-path-closed-on-time` | established / closed_as_accepted | supported / anchor_matches | referral, receipt, acknowledgement, acceptance, closure observed |

The verifier does not hold the designated role, the order of the slots or the closure window, so
the role checks, the order and the lateness of a step (cases 6 and 8, and `closed_late`) are this
corpus's rules and are not in that comparison. In case 6 the authority read at the referral
instant matches, and the narrowing before the acknowledgement is read from the version history.

## Registration

- URI: `https://probityai.github.io/agent-evidence-vectors/predicate/v1/responsibility-escalation`,
  defined here. This repository mints the records and owns the record shape.
- Envelope: a bare JSON record, not an in-toto Statement: `contractId` (the URI), `recordId`,
  `decision`, `authority` (the reference, its versions, what it resolved to and where it is read),
  `escalation` (the designated role, the evidence slots and the closure window) and `evaluatedAt`.
  The outcome is derivable from the record alone.
- Compatibility: v1 never changes. A new outcome token, a changed check order or a change to the
  slots is a new URI beside v1.

## What it does not test

Reference formats, identifier syntax, how a receiver finds the version in force, and the
sealed or hold-out round of the list's test plan. Every member is synthetic. Regenerate with
`python3 corpora/vectors-responsibility-escalation/gen_vectors.py`.
