# ACI conformance corpus

Nineteen checks over ACI Draft Specification v0.9, one per normative sentence,
and 26 deployments that force them.

[![Checked with Probity](https://img.shields.io/badge/checked-with_Probity-0969da?logo=data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAMAAABEpIrGAAAAkFBMVEX8%2B%2Bzr5NPgyrfKyLnSq5Wzo4tWltqRkZI2kPU1kvk1j%2FMwkPgzjfI2jO80jO40jO3MdWOZc1SLblN1aFxxXFJzVDY2i%2B40i%2B00i%2Bw0i%2Bs0ius1iOZAapwugNYtdbUqaq0qV4tkRzJXOB47Oz43JRkjNEYiHBwlFxIfFxMcEg0XEQ0WEAwXDAUWCAEOCQcJAgCa503RAAAB3klEQVR42rWT2ZacIBCGceHYoN240SK2Crig4vL%2BbxfszJyZTmaSm6S4rI9a%2FwK3vxj41wDj5E9AwS%2Foxjn7DmARqgVHCBHyJcBxJeZtEG2Nv4hAGEPXYVumddvWAbFfgJJECDfDukxa63ldmw%2FiCTCEK%2BteFzNbQI%2BbQPwzwKJGjNO2LMacxNqK1wgcNfO2mqfbHMs8NEkeXT8AjurRTKfbMlqOa5vFyc8cZclu4PSvWptlPlOMeb4PsQu78MoYQWFIwKUet0nPZl%2FMki1H3x%2FKd1PVhhdkS2tDgM7m9bR3XX8EXtYde59SSVVXNx2NMwuIbbGl74HUu%2BcFXrArSpXqlVSpGz8sUG%2FjoCej1RHA6ZAgl1SmUvVUQjduEGDIdt0MxuwjCHYNAZSwT1IbhaZ%2BFt7BrUAXbguxnx3gZ9AJVJLal0hKaYv4OShGbu249Z4F4jhQ1PcpTUYLDBF5WxZB9dBB14O%2Bm6eu48QQpjBXIizf113iS9sF0LYxZMD1PODbVvtznu96sGOrWyFEiwQEwHNcC8gaF58UxfG1qiqMqzx2AACJ0i0qXyRXEIwjwnD1SBOYdKJ%2B7vxF1eRUaxGF9ePRVgiX3xxOccdhiK5v6v%2Fysgp2Z%2BR%2F3ebv9gP5RU8tSdZhDwAAAABJRU5ErkJggg%3D%3D)](https://github.com/probityai/probity)

```sh
go build -o aee-verify ./cmd/aee-verify
./aee-verify vectors-aci
```

Exit 0 when every member behaves as `MANIFEST.json` declares, 1 when one does
not and is named, 2 when the corpus could not be judged.

## What a member is

Every other corpus here names a member after the digest of one file. An ACI
member is a whole DEPLOYMENT: the several manifests an organization publishes at
its domain, plus the discovery chain that finds them, and half the requirements
are about how those files agree with each other. So a deployment is serialised
into one file, `deployment-members/v<16 hex>.json`, holding each published path
against that file's exact text. The identifier stays a digest of the member's
own bytes, which is what lets a flipped byte name the member it was flipped in.

## The three verdicts

| verdict | meaning | members |
|---|---|---|
| `accept` | every check passes | 1 |
| `indeterminate` | every MUST is met and a SHOULD is not | 4 |
| `reject` | at least one MUST is not met | 21 |

Two verdicts would put a deployment that meets every MUST and misses a SHOULD
into the wrong box in both directions: calling it a reject reports more than the
specification says, and calling it an accept discards the finding. Section 4.2
makes publishing `/.well-known/aci` a SHOULD while the three fields it must then
carry are a MUST, so `ACI-DIS-002` is a warning in one member and a refusal in
another. Writing the reachability cases is what surfaced that split.

## The checks

`MANIFEST.json` carries the table and `corpora/aci.go` carries its own copy; the
reader asserts the two agree in both directions, because a check in one and not
the other is a requirement nothing forces. A corpus-level check also refuses when
any code is declared and no member forces it: without it, nineteen checks and one
member would score full marks.

## The specification's own examples are members

Six of the 26 are the deployments shipped with the specification, vendored at
`specCommit`. Four do not satisfy the text they illustrate and are pinned as
expected non-accepts naming the finding they demonstrate, rather than corrected:
a corpus that quietly fixed the specification's examples would certify against a
document nobody published.

| example | verdict | codes | finding |
|---|---|---|---|
| `minimal` | reject | `ACI-DIS-001`, `ACI-DIS-002`, `ACI-LVL-001`, `ACI-TS-001` | S-11 |
| `level1` | indeterminate | `ACI-DIS-002`, `ACI-TS-001` | S-3 |
| `level2` | reject | `ACI-DIS-002`, `ACI-EXT-001`, `ACI-TS-001` | S-4 |
| `level3` | reject | `ACI-DIS-002`, `ACI-EXT-001`, `ACI-TS-001` | S-4 |
| `level4` | reject | `ACI-BLK-001`, `ACI-DIS-002`, `ACI-EXT-001`, `ACI-TS-001` | S-4 |
| `empirelabs` | reject | `ACI-DIS-001`, `ACI-DIS-002`, `ACI-EXT-001`, `ACI-LVL-001`, `ACI-TS-001` | S-11 |

`level1` is the only one that meets every MUST at the level it claims.

## What this corpus does not decide

Section 4.1 does not say whether a RELATIVE `llms.txt` target satisfies it. The
section's own example and the reference deployment both use absolute URLs and
all five example files use relative ones, so the reader matches a relative target
by basename and the ambiguity is reported here rather than settled in a check.
Finding S-6 carries the measurement.

## Regenerating

```sh
python3 vectors-aci/gen_vectors.py
```

Every member file and `MANIFEST.json` are emitted from the deployment fixtures in
`deployments/`, and `scripts/regenerability-gate.py` runs the generator into a
copy of the tree and compares. Never edit a generated file by hand.
