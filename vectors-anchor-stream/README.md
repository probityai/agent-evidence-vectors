# ANCHORS stream conformance suite

Conformance vectors for the append-only anchor stream and digest sidecar
verified by `anchors_verify.py`, published by `aos-standard/catalog` and pinned
here at the tag `anchors-verify-v0.4`, commit `44c40ba`. The contract text that
tag ships is vendored at `spec-vendored/anchors-verify-44c40ba.md` and its
sha256 is `specDigest` in `MANIFEST.json`.

## The reason is the assertion, not the verdict

A verifier reaches a verdict through more than one branch. Some of those
branches stop before the property under test is ever evaluated: an unrecognised
version string, a field of the wrong type, a guard on a shape rather than on a
value. A stop like that produces a verdict word, and the verdict word is
indistinguishable from the one the same verifier would print after actually
checking. When the guard happens to stop on the correct side, nothing catches
it, and the check that was supposed to run has silently stopped running.

So every reject member here declares a stop reason as well as an outcome, and
`run_verifier.py` scores both. A member that reaches the expected verdict from
the wrong branch is reported separately, in its own line, because it is the
failure that a verdict column cannot show you. Against the pinned tag this
corpus finds two such members; both reach the correct verdict and neither
evaluates the rule it appears to be enforcing.

The stop-reason vocabulary is the corpus's own, and `reason-map/` translates it
onto one implementation's prose. That file exists only because the stream
format publishes no reason codes. A code in the format deletes it.

## The platform bytes are pinned

A verifier for this format fetches the witness repository over the network
while it runs, which makes the verdict a function of what that repository holds
at fetch time. One member of this corpus is exactly that: the stream bundled
with the pinned tag, presented with a default branch that has grown since the
tag was cut. Nothing about the bundled artifact changed and its verdict did.

So each member carries a third file, `witness/<id>.json`, holding the bytes the
platform serves for every commit the member names, the bytes of the default
branch, and whether each commit is reachable from that branch. Reachability is
a fact about the platform rather than about the bytes, so it is carried rather
than derived. `run_verifier.py` replaces the module's fetchers with a function
that raises, so a verifier that reaches for a socket fails the run instead of
returning a number nobody else can reproduce.

## One member pair comes from a real stream

Tetsurohhori (aos-standard/catalog) published a 73-line stream and its sidecar whose
last line carries no trailing newline in the unterminated form. `baseline/external-unterminated-final-line/`
holds the terminated stream and sidecar with their provenance. The pair built from it
checks one thing: a verifier that drops the final line when it is unterminated must be
caught, because the sidecar digest then no longer matches. The accept member is the
stream as published (`VERIFY PARTIAL`, exit 3). The reject member is the same stream
with its last byte removed, presented with the same sidecar (`VERIFY FAILED`, stop
reason `digest-mismatch`). Thanks to Tetsurohhori for the stream and the pair.

## Identifiers name the bytes, not the answer

Each identifier is a digest of the member's own three files. There is no
`accept/` directory, no `reject/` directory and no verdict in any name; the
expectation lives in `MANIFEST.json`, which is where a scoring harness reads
it. This is not a stylistic choice. The sibling corpus in this repository
carried its verdict twice, once in a filename prefix and once in the directory
around it, and a classifier over the identifier alone predicted accept or
reject with a separability of 1.0000 against a permutation null of 0.5879: a
verifier could have certified against that suite without opening a file.
`aee-verify` recomputes each identifier from the bytes it names, so an
edit that does not regenerate leaves a name describing bytes that are gone.

## Layout

| path | what it is |
|---|---|
| `baseline/` | the stream, sidecar and witness snapshots the tag published, unmodified, plus `baseline/external-unterminated-final-line/`, a real stream and sidecar contributed from outside |
| `streams/` | the presented stream of each member |
| `sidecars/` | the digest sidecar presented with it |
| `witness/` | the platform bytes a run reads, and per commit whether it is reachable |
| `reason-map/` | the corpus stop-reason vocabulary mapped onto one implementation's prose |
| `spec-vendored/` | the contract text this corpus certifies against, pinned by digest |
| `MANIFEST.json` | machine-readable expectations, conditions, counts and corpus digest |
| `INDEX.md` | every member in one table |
| `gen_vectors.py` | regenerates the corpus byte-identically |
| `run_verifier.py` | runs the corpus against a verifier and reports outcome and stop reason |

## Running it

```
aee-verify vectors-anchor-stream/  # self-check, from the repository root
python3 gen_vectors.py             # regenerate, byte-identically
python3 gen_vectors.py --check     # refuse a tree the generator does not emit
python3 run_verifier.py --verifier /path/to/anchors_verify.py
```

`aee-verify` is the one harness for every corpus in this repository. It reads
the `suite` field of a `MANIFEST.json`, judges the members that suite declares,
and refuses by name a suite it does not know. Each corpus used to carry a
Python self-check of its own, so the command a reader was told to run differed
per corpus and three of the six were wired into no workflow at all. Build it
with `go build -o aee-verify ./cmd/aee-verify`.

`run_verifier.py` takes `--verifier` more than once with a matching `--label`,
which is how one run reports every published tag side by side.

`aee-verify` refuses a corpus in which a reject condition has no
accepting twin. A suite of rejections alone awards full marks to a verifier
that rejects every input, and that is the one verifier certifying nothing.

## What this corpus is not

It is not a security assessment and it makes no claim about any deployment. It
is a set of inputs with declared expectations, and a run against a given build
is an observation about that build on the day it ran. Three of the limits the
verifier's own documentation names as out of scope are out of scope here too:
there is no signature suite, so equivocation between continuations shown to
different auditors is unreachable; the stream tip is unattested until the next
binding; and a rewritten witness history breaks every history-dependent check.
Members that would need any of those are absent rather than asserted.
