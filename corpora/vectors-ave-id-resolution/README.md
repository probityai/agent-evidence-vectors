# AVE id resolution vectors

[![Checked with Probity](https://img.shields.io/badge/checked-with_Probity-blue?style=flat-square&logo=data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAMAAABEpIrGAAAAkFBMVEX8%2B%2Bzr5NPgyrfKyLnSq5Wzo4tWltqRkZI2kPU1kvk1j%2FMwkPgzjfI2jO80jO40jO3MdWOZc1SLblN1aFxxXFJzVDY2i%2B40i%2B00i%2Bw0i%2Bs0ius1iOZAapwugNYtdbUqaq0qV4tkRzJXOB47Oz43JRkjNEYiHBwlFxIfFxMcEg0XEQ0WEAwXDAUWCAEOCQcJAgCa503RAAAB3klEQVR42rWT2ZacIBCGceHYoN240SK2Crig4vL%2BbxfszJyZTmaSm6S4rI9a%2FwK3vxj41wDj5E9AwS%2Foxjn7DmARqgVHCBHyJcBxJeZtEG2Nv4hAGEPXYVumddvWAbFfgJJECDfDukxa63ldmw%2FiCTCEK%2BteFzNbQI%2BbQPwzwKJGjNO2LMacxNqK1wgcNfO2mqfbHMs8NEkeXT8AjurRTKfbMlqOa5vFyc8cZclu4PSvWptlPlOMeb4PsQu78MoYQWFIwKUet0nPZl%2FMki1H3x%2FKd1PVhhdkS2tDgM7m9bR3XX8EXtYde59SSVVXNx2NMwuIbbGl74HUu%2BcFXrArSpXqlVSpGz8sUG%2FjoCej1RHA6ZAgl1SmUvVUQjduEGDIdt0MxuwjCHYNAZSwT1IbhaZ%2BFt7BrUAXbguxnx3gZ9AJVJLal0hKaYv4OShGbu249Z4F4jhQ1PcpTUYLDBF5WxZB9dBB14O%2Bm6eu48QQpjBXIizf113iS9sF0LYxZMD1PODbVvtznu96sGOrWyFEiwQEwHNcC8gaF58UxfG1qiqMqzx2AACJ0i0qXyRXEIwjwnD1SBOYdKJ%2B7vxF1eRUaxGF9ePRVgiX3xxOccdhiK5v6v%2Fysgp2Z%2BR%2F3ebv9gP5RU8tSdZhDwAAAABJRU5ErkJggg%3D%3D)](https://github.com/probityai/probity)

Cases for `ave-id-resolution/v1`: a tool's findings output, in SARIF or in JSON, names vulnerability classes by [AVE](https://github.com/aveproject/ave) id, and every one of those ids must resolve to an `active` record in a pinned AVE snapshot. The check is tool-neutral: it reads any scanner's output and names no tool.

The case design is the AVE project's, supplied by its maintainer chaksaray in [#352](https://github.com/probityai/agent-evidence-vectors/issues/352): the v1.2.0 pin, the four cases (an active id resolves, an unknown id fails, a malformed id fails, a record that is not active fails), and the rule that any status other than `active` fails, without assuming the list of statuses is complete. AVE's input is that fixture and one review by its maintainers; it implies no endorsement or integration between the projects, and maintenance is ours.

## Snapshots

`snapshots/<release>/` holds the release assets of each pinned AVE catalog release byte for byte, with the release's own `SHA256SUMS`. `MANIFEST.json` pins each one by tag, source commit and the SHA-256 of `ave-records.json`, and the generator and the checker refuse bytes that differ from the pin or from `SHA256SUMS`. v1.2.0 carries only `active` records, so the not-active cases use v1.3.0, in which some records are `rejected`. `not-active-sarif` and `not-active-sarif-under-v1.2.0` are the same output judged against the two pins, which is why the snapshot is pinned by digest rather than read from `latest`.

## Running it

```sh
python3 corpora/vectors-ave-id-resolution/resolve_ids.py scan.sarif \
  --snapshot corpora/vectors-ave-id-resolution/snapshots/v1.2.0/ave-records.json \
  --sha256 92e002e98cdd10f5de36e0ccfa80696b623cdadf302cc4d884f2a33b7fd94390
```

The checker uses the standard library only and fetches nothing. It prints one JSON object (`verdict`, `codes`, `findings`, `snapshot`) and exits 0 when every id resolves, 1 when any fails, 2 when it cannot judge (unreadable input, or snapshot bytes that are not the pinned ones) and 3 when the output carries no AVE id. Its codes are `id-malformed`, `id-unknown`, `id-not-active` and `run-snapshot-differs`; the last fires when the output declares `ave_records_sha256` for records other than the pinned snapshot. Where it reads ids in each format is in the docstring of `resolve_ids.py`.

`check_vectors.py` judges every member and shows each rule is produced by a member. Another resolution checker is scored the same way:

```sh
python3 corpora/vectors-ave-id-resolution/check_vectors.py --verifier './my-check'
```

The verifier runs as `<verifier> <output-file> <snapshot-file> <sha256>`, prints one JSON object with `verdict` and `codes` on its last line, and exits as the reference checker does. `--decision-only` compares verdicts alone. `INDEX.md` lists the members. Regenerate them with `python3 corpora/vectors-ave-id-resolution/gen_vectors.py`; the tests in `tests/` require byte-identical output and show that switching any rule off changes the answer of every member that names it.

## Adding a sample

A sample from any project goes in by pull request as a new entry in `MEMBERS` in `gen_vectors.py`. Its output is written to `cases/<member-id>/output.sarif` or `output.json`, with the snapshot it is judged against and the verdict and codes it must get, and the generator refuses it when the checker disagrees. A new AVE release joins `snapshots/` the same way, with its assets unchanged and its pin added to `SNAPSHOTS`.

Passing these cases does not establish that a finding is correct or that a tool maps its rules to the right class. It establishes that every class the output names exists and is active in the catalog the run is pinned to.
