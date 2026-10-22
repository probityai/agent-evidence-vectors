# TRACE registry anchor comparison

This repository runs its [registry anchor corpus](../../vectors-trace-anchor/README.md)
against TRACE's own Level 2 anchor check, TR-ANC-002 in the TRACE conformance
suite. The comparison runs here, so TRACE does not need our package in its CI.

The [workflow](../../.github/workflows/trace-anchor-tr-anc.yml) fetches the five
standard-library files that check imports from each public TRACE commit in
[`pins.json`](pins.json), refuses any file whose SHA-256 differs from its pin,
and replays all 27 cases through [`tr_anc_reader.py`](tr_anc_reader.py),
compared on the decision. [`compare.py`](compare.py) then holds each pin to the
exact set of disagreements recorded for it: a new one fails the job, and so
does a recorded one that has gone away.

| Pin | Commit | Agrees | Disagrees |
| --- | --- | --- | --- |
| main before trace-spec#533 | `6fb2570` | 19 of 27 | 8 |
| trace-spec#533 head | `95e160a` | 26 of 27 | 1 |

The job runs on relevant changes, weekly and on manual request. It does not
move a pin; a new TRACE commit is compared by adding a pin with its digests and
its measured disagreements.

These checks establish results for the pinned sources and these inputs. They do
not establish an upstream merge, a standards decision, or any deployment.
