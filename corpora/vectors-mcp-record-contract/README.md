# Cross-run record contract

The subject under test here is not a protocol message. It is a **run record**:
the artifact a cross-implementation claim rests on when it says two
implementations agree.

[![Checked with Probity](https://img.shields.io/badge/checked-with_Probity-0969da?logo=data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAMAAABEpIrGAAAAkFBMVEX8%2B%2Bzr5NPgyrfKyLnSq5Wzo4tWltqRkZI2kPU1kvk1j%2FMwkPgzjfI2jO80jO40jO3MdWOZc1SLblN1aFxxXFJzVDY2i%2B40i%2B00i%2Bw0i%2Bs0ius1iOZAapwugNYtdbUqaq0qV4tkRzJXOB47Oz43JRkjNEYiHBwlFxIfFxMcEg0XEQ0WEAwXDAUWCAEOCQcJAgCa503RAAAB3klEQVR42rWT2ZacIBCGceHYoN240SK2Crig4vL%2BbxfszJyZTmaSm6S4rI9a%2FwK3vxj41wDj5E9AwS%2Foxjn7DmARqgVHCBHyJcBxJeZtEG2Nv4hAGEPXYVumddvWAbFfgJJECDfDukxa63ldmw%2FiCTCEK%2BteFzNbQI%2BbQPwzwKJGjNO2LMacxNqK1wgcNfO2mqfbHMs8NEkeXT8AjurRTKfbMlqOa5vFyc8cZclu4PSvWptlPlOMeb4PsQu78MoYQWFIwKUet0nPZl%2FMki1H3x%2FKd1PVhhdkS2tDgM7m9bR3XX8EXtYde59SSVVXNx2NMwuIbbGl74HUu%2BcFXrArSpXqlVSpGz8sUG%2FjoCej1RHA6ZAgl1SmUvVUQjduEGDIdt0MxuwjCHYNAZSwT1IbhaZ%2BFt7BrUAXbguxnx3gZ9AJVJLal0hKaYv4OShGbu249Z4F4jhQ1PcpTUYLDBF5WxZB9dBB14O%2Bm6eu48QQpjBXIizf113iS9sF0LYxZMD1PODbVvtznu96sGOrWyFEiwQEwHNcC8gaF58UxfG1qiqMqzx2AACJ0i0qXyRXEIwjwnD1SBOYdKJ%2B7vxF1eRUaxGF9ePRVgiX3xxOccdhiK5v6v%2Fysgp2Z%2BR%2F3ebv9gP5RU8tSdZhDwAAAABJRU5ErkJggg%3D%3D)](https://github.com/probityai/probity)

The rule is in `../docs/INTEROP-EVIDENCE.md` and `check_run_record.py` is that
rule as code. This corpus is the checker's own conformance suite, so the rule
is measured rather than asserted beside itself. `aee-verify` runs the
checker over every member and refuses when an answer differs from the one the
member declares.

## Three answers, kept apart

| answer | question |
|---|---|
| `recheckable` | can a third party obtain the same result from what is published |
| `figureMeansWhatItSays` | does the headline agree with its own counting rule |
| `independence` | independent, self-report, or undeclared |

A record can be fully re-checkable, carry a figure nobody should quote, and be
a declared self-report. One member here is exactly that, and it is the member
that separates a checker reading the record from a checker reading the summary.

Independence is three-valued rather than a pass. A run of somebody else's
vectors by their author is worth publishing and is not independent evidence,
and only an undeclared record is a defect: failing a declared self-report would
push records towards leaving the declaration out, which is the opposite of what
the field is for.

## Every member is synthetic

Each is shaped after a defect observed in published cross-run claims in open
specification threads. None transcribes or attributes a particular claim, and
no party is named anywhere in this directory. The shape is the thing under
test, and a corpus that named parties would be an accusation with a schema.

A reject member differs from an accepting twin in exactly one field, and its
condition says which axis it fails. `aee-verify` refuses a reject member
declaring failures on two axes, because a member failing two cannot tell you
which rule caught it.

## Layout

| path | what it is |
|---|---|
| `records/` | one run record per member, named after a digest of its own declaration |
| `MANIFEST.json` | the conditions, the expectations, counts and corpus digest |
| `INDEX.md` | every member in one table |
| `check_run_record.py` | the criterion, as a checker; usable on any record, not only these |
| `gen_vectors.py` | regenerates the corpus byte-identically |
| `check_run_record.py` | the criterion as a standalone tool, for a record of your own |

## Running it

```
python3 gen_vectors.py                       # regenerate, byte-identically
python3 gen_vectors.py --check               # refuse a tree the generator does not emit
aee-verify vectors-mcp-record-contract/      # self-check, including the criterion
python3 check_run_record.py records/*.json   # the criterion on its own
```

`check_run_record.py` takes any run record in the shape `records/` uses, so a
project publishing one can check it before publishing rather than after being
asked about it.

## What this corpus does not do

It says nothing about whether any claim is true. A record failing the rule is
an assertion, which is a statement about what a reader can do with it. A
self-report from a careful engineer is frequently correct and is not evidence,
and holding those two apart is the whole content of the suite.
