# HTX case pairs

Accept and reject cases for requirements of the Trust over IP
[HTX task force](https://github.com/trustoverip/dtgwg-htx-tf) patterns. Each reject
differs from its accept control by exactly one field, so a checker that passes a
reject has missed that one field. Discussion:
[dtgwg-htx-tf#44](https://github.com/trustoverip/dtgwg-htx-tf/discussions/44).

[![Checked with Probity](https://img.shields.io/badge/checked-with_Probity-blue?style=flat-square&logo=data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAMAAABEpIrGAAAAkFBMVEX8%2B%2Bzr5NPgyrfKyLnSq5Wzo4tWltqRkZI2kPU1kvk1j%2FMwkPgzjfI2jO80jO40jO3MdWOZc1SLblN1aFxxXFJzVDY2i%2B40i%2B00i%2Bw0i%2Bs0ius1iOZAapwugNYtdbUqaq0qV4tkRzJXOB47Oz43JRkjNEYiHBwlFxIfFxMcEg0XEQ0WEAwXDAUWCAEOCQcJAgCa503RAAAB3klEQVR42rWT2ZacIBCGceHYoN240SK2Crig4vL%2BbxfszJyZTmaSm6S4rI9a%2FwK3vxj41wDj5E9AwS%2Foxjn7DmARqgVHCBHyJcBxJeZtEG2Nv4hAGEPXYVumddvWAbFfgJJECDfDukxa63ldmw%2FiCTCEK%2BteFzNbQI%2BbQPwzwKJGjNO2LMacxNqK1wgcNfO2mqfbHMs8NEkeXT8AjurRTKfbMlqOa5vFyc8cZclu4PSvWptlPlOMeb4PsQu78MoYQWFIwKUet0nPZl%2FMki1H3x%2FKd1PVhhdkS2tDgM7m9bR3XX8EXtYde59SSVVXNx2NMwuIbbGl74HUu%2BcFXrArSpXqlVSpGz8sUG%2FjoCej1RHA6ZAgl1SmUvVUQjduEGDIdt0MxuwjCHYNAZSwT1IbhaZ%2BFt7BrUAXbguxnx3gZ9AJVJLal0hKaYv4OShGbu249Z4F4jhQ1PcpTUYLDBF5WxZB9dBB14O%2Bm6eu48QQpjBXIizf113iS9sF0LYxZMD1PODbVvtznu96sGOrWyFEiwQEwHNcC8gaF58UxfG1qiqMqzx2AACJ0i0qXyRXEIwjwnD1SBOYdKJ%2B7vxF1eRUaxGF9ePRVgiX3xxOccdhiK5v6v%2Fysgp2Z%2BR%2F3ebv9gP5RU8tSdZhDwAAAABJRU5ErkJggg%3D%3D)](https://github.com/probityai/probity)

For anyone who implements an HTX pattern and wants a case set to check the implementation against.

```sh
pip install agent-evidence-vectors
agent-evidence-vectors --corpus vectors-htx-cases
python3 corpora/vectors-htx-cases/check_vectors.py --verifier './verifier'
```

A verifier takes `record.json --json`, prints `{"decision": ..., "reason": ...}` and exits 0
for `allow` and 1 for `deny`. In HTX terms `allow` is `accept` and `deny` is `reject`;
`MANIFEST.json` carries both, the second as `htxExpected`.

Conformance claim form: "Conformant to HTX P18.01 section 6 at htx-cases `<version>`".

## Pair 1: changed details do not inherit an approval

[P18.01](https://github.com/trustoverip/dtgwg-htx-tf/blob/main/docs/patterns/p18-01.md)
section 6: transaction controls must prevent changed details from inheriting an earlier approval.
A record holds `confirmation` (the outcome and the request the person confirmed) and `action`
(the request about to be carried out). The reader checks in order:

1. `not-confirmed`: the confirmation outcome is not `confirmed`.
2. `request-changed-after-confirmation`: the action's request is not equal to the confirmed
   one as parsed JSON.

The accept control carries the same request twice. The rejects change the beneficiary, the
amount, the currency or the scope of the action's request, one per case, and one declines the
confirmation with the request unchanged.

## Pair 2: what is disclosed is within what was agreed

This requirement is ours, offered as a proposal: the HTX pattern pages for it are not written
yet. It sits under core pattern TP2, in the families P08 (understandable requests) and P10
(meaningful choice and minimum disclosure), at trust moment T6. The requirement is that what is
disclosed must be within what the person agreed to share, for the stated purpose. A record
holds `consent` (outcome, purpose, recipient, the required and granted optional fields, and the
refused optional fields) and `disclosure` (purpose, recipient and fields). The reader checks in
order:

1. `not-agreed`: fields are disclosed and the consent outcome is not `agreed`.
2. `purpose-changed` and 3. `recipient-changed`: either differs from the consented one.
4. `refused-field-disclosed`: a disclosed field is one the person refused.
5. `field-not-consented`: a disclosed field is neither required nor a granted optional one.

A refused field is also outside consent, so check 4 comes first and names it. A declined consent
with nothing disclosed discloses nothing, and no case covers it. The accept control discloses
only `date_of_birth`. Each reject changes one field of it: an added field the person never
mentioned, the refused `home_address` sent anyway, another purpose, another recipient, or a
declined outcome with the fields still disclosed.

## Synthetic, and what it does not test

Every member is synthetic. Passing the cases does not show that a confirmation was given by
the person, or that a disclosed value is true. Regenerate with
`python3 corpora/vectors-htx-cases/gen_vectors.py`; counts are in `MANIFEST.json`.
