# Agent Passport corpus revision 2: independent reader result

Probity's reader for APS/AEOESS's 20 public synthetic Agent Passport cases, run over
revision 2 of the corpus. It does not import or call the APS SDK. The
[report](report.json) is the run's output. It follows the
[revision 1 result](../aps-corrected20-2026-10-10/README.md), which stays as published.

Revision 2 is `fixtures/agent-passport-v2/agent-passport-vectors-v2-r2.json` in
agent-passport-system/agent-passport-system at
`e061462cea95b029203374496bbd14488d8d2993` (merge of #224), SHA-256
`9bd1f1849910c85f0555baf8efaa529aa9d057dce13c24606285b8643a003b89`. It supersedes the
`407ca2d5` file, SHA-256 `9fce76dbf13de9749a2ef52c8dedecce08e4874da0203b39a7d941eb479b5ac5`.
APS retains corpus authorship and Apache-2.0 licensing in [producer/](producer/LICENSE).

## Result

The source records 4 valid, 11 invalid, 3 indeterminate and 2 unsupported outcomes. This
reader returns the same four counts. All 20 final outcomes, all 20 diagnostic layer maps,
all 20 resolver-request lists and the 3 frozen preimages agree with the file. There is no
declared difference: `status` is PASS with an empty `mismatches` list.

Against revision 1, the reader's raw byte checks (derived passport ids, signature
validity, public keys, preimages) are identical on all 20 cases, and its 20 final
outcomes are unchanged. The producer moved three expected outcomes to the ones the
revision 1 report returned (`did-web-resolver-not-found` indeterminate,
`version-changed` and `record-type-changed` unsupported), so agreement here confirms the
revision. It is not a new blind test. The reader never saw the revision 2 answers
change its own reading.

## What changed in the reader

[reader-diff-from-r1.diff](reader-diff-from-r1.diff) is the whole change from the revision
1 reader (SHA-256 `1d9b8fc840a974796b2098d367e37599cbce4d7455186bbeeeb7f3879c873bda`):
the fixture pin, a check that the file is revision 2 of the pinned family, the
`structure` layer label `unsupported` where the revision 2 legend uses it (two cases),
and the removal of the three expected-divergence exemptions. The unsupported
determination now precedes the closed-object check, as the revision 2 `layers_legend`
orders it: a string `record_type` other than `aps.agent-passport`, or that type with a
string `version` other than `2.0`, is unsupported; a missing or non-string value is
still invalid. No pinned case exercises that ordering, so the 20 results do not depend on it.

## Replay

Linux x86-64, from this directory:

```sh
uv venv --python 3.14.7 .reader-venv
uv pip install --python .reader-venv/bin/python --require-hashes --only-binary :all: -r reader-requirements.txt
.reader-venv/bin/python -I -B read_corpus.py --fixture producer/agent-passport-vectors-v2-r2.json --output replay.json
```

`replay.json` equals [report.json](report.json) except for the `at` timestamp. The
reader refuses any fixture whose SHA-256 is not the revision 2 value above.
[provenance.json](provenance.json) names the run: reader source hash, interpreter,
installed distributions, command and exit code.

## Limits

The reader supports the corpus's printable ASCII subset and is not a general RFC 8785
qualification. Ed25519 checks use cryptography 50.0.2 over OpenSSL, so there is no
independent cryptographic-backend claim. Resolver answers and evaluation times are
supplied; historical authority, authenticated lookup and principal binding are untested.
The expected answers were public before the reader ran, and the reader emits its checks
and its comparison in one report. Twenty public synthetic cases are not a deployment
population. No outside use of this reader, maintainer acceptance, live host adoption,
federation enrollment or commercial result is established.
