# Recordings of published builds

One file per build of `anchors_verify.py` that this corpus has been run against.
`anchors-verify-<tag>.json` is the agreement recording `run_verifier.py --expect`
ratchets against: member id, `true` when the build agreed on verdict, exit code
and stop reason. `anchors-verify-<tag>.observations.json` is the full table from
the same run (`--json`): per member the verdict, exit code, the corpus failure
class the build's stop text falls in, and the raw stop text itself, kept beside
the row and never rewritten.

## anchors-verify-v0.12, `aos-standard/catalog` at `df8b9ee4051e25c64e8d953d90eec005163421f1`

Run 2026-11-23 against this corpus (34 members, corpus digest
`b63cd1c26fc05365276fe950b6e6a3dbd0b48db8dc10337b56bb446c759110b5`), through
`python3 run_verifier.py --verifier <anchors_verify.py at df8b9ee> --label anchors-verify-v0.12 --reason-map reason-map/aos-anchors-verify-v0.12.json --json`.

**32 of 34 members agree on verdict, exit code and normalized failure class.**
The two that do not are the two `ans-c-3` rows below. The build ships its own
diagnostic wording and this corpus compares the class its wording falls in
rather than asking for the wording to change: the maintainer's wording stays as
published, and the map in `reason-map/aos-anchors-verify-v0.12.json` follows the
build. With the v0.10 map the count is 31 of 34, because one stop text
(`position binding at line 19: names no witness repository`) was reworded and
the older needle no longer matched it.

### Semantic disagreement: `ans-c-3`, PARTIAL versus FAILED

| member | corpus expects | build returns | raw stop text |
| --- | --- | --- | --- |
| `v8c0edba09c428917` | `VERIFY FAILED`, exit 1, `sidecar-coverage` | `VERIFY PARTIAL`, exit 3 | `VERIFY PARTIAL: lines=24 digests=18 witness_repo=aos-standard/catalog witness_commit=0eb69bf9f26f03b8d4fbce3b3b64ac46e10e1582 attested_prefix_lines=18` |
| `vd6eecc03efb27ebd` | `VERIFY FAILED`, exit 1, `sidecar-coverage` | `VERIFY PARTIAL`, exit 3 | `VERIFY PARTIAL: lines=24 digests=18 witness_repo=aos-standard/catalog witness_commit=0eb69bf9f26f03b8d4fbce3b3b64ac46e10e1582 attested_prefix_lines=18` |

Both present a sidecar that covers 18 of 24 stream lines. The corpus condition
`ans-c-3` (basis `proposed`) says a line with no sidecar entry has not been
verified and the verdict must say so as a refusal. The build reports it as
`VERIFY PARTIAL`, exit 3, naming the gap in the count (`digests=18`,
`attested_prefix_lines=18`); its maintainer keeps that reading because
`PARTIAL` is the contract's verdict for lines beyond the attested prefix, and
has said that if the objection is the name, he would change the text before the
exit code. The row is a
disagreement about which verdict the proposed condition earns, not a stop
reached from the wrong branch: the build does evaluate the coverage and prints
it. It stays recorded as disagreeing so the ratchet is silent about it and
fires if the build ever moves to either side by accident.

### What moved since `anchors-verify-v0.10`

| member | condition | v0.10 | v0.12 | moved at |
| --- | --- | --- | --- | --- |
| `v4598881bb94db9a9` | `ans-c-2` | `VERIFY PARTIAL`, exit 3 | `VERIFY FAILED`, exit 1, `digest-mismatch` (`digest mismatch at line 24`) | `anchors-verify-v0.11`, commit `55a3d85` |
| `vfc54e61742cea5f5` | `ans-c-10` | `VERIFY FAILED`, exit 1, `truncation vector 2: presented stream shorter than main branch (24 vs ...` | `VERIFY PARTIAL`, exit 3, as expected | `anchors-verify-v0.12`, `df8b9ee` |
| `vfccf46c02cc12618` | `ans-c-9` | `VERIFY PARTIAL`, exit 3 (the expected repository name stood in for the one the stream names) | `VERIFY FAILED`, exit 1, class `binding-repo-absent` (`position binding at line 19: names no witness repository`) | `anchors-verify-v0.12`, `df8b9ee` |

Two members were added to the corpus after the 32-member run the thread
discusses, the real-stream pair `v25a148d9df730b88` (reject) and
`v3c142a4f8828f505` (accept) under `ans-c-2`. Both agree at v0.12.

### The ledger row this run cites

`VCL-0024`, `externally_broken`, in the `aos-standard/catalog` ledger, attributed
to this corpus's author: the documented tag-fixed run at `anchors-verify-v0.10`
exited 1 on an honest stream, and the published claim that it reproduces
without reading `main` was false. `anchors-verify-v0.12` at `df8b9ee` is the
build that fixes it (a byte-prefix comparison with the default branch, and an
empty binding repository name fails closed).
