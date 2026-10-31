# Source and attribution map

Probity wrote the controls in this directory. Four submissions motivated the
separate conclusions. Their source revisions and tested files are pinned in
`SOURCE-PINS.json`. The original submissions keep their own authorship and
mechanisms.

| Source | Contribution to these controls | Evidence boundary |
| --- | --- | --- |
| [PriorSeal exact-call matrix](https://github.com/imokokok/PriorSeal/pull/15) | Keep intent commitment, signer recovery and call-envelope comparison separate. | Its standalone reader recovers the declared hash. Its producer `verifyAuthorization` function reconstructs the intent and rejects a changed synthetic preimage. |
| [AEOESS target-subject candidate suite](https://github.com/aeoess/federation-port/pull/6) | Separate reported subject equality from destination authorization and supplied observation. | The merged candidate suite tests declared targets. It does not adopt the open specification draft or prove dispatch. |
| [Frequency synthetic fixture](https://github.com/altrudev/frequency-open-evidence-lab/tree/f5bc64d883564ac5cc6f23f96d346ed8ad6528ae) | Preserve authorization, historical reporting and current supplied-state comparisons independently. | Its authorization and observations are supplied assertions. A changed current string does not disprove a historical report. |
| [Scanner decision fixture](https://github.com/sushant-me/reputation/blob/95717bd4c84883346839ce3407862b4cbcb504e7/case2_truncation_exit_code.py) | Preserve a printed truncation notice and the process exit as separate facts. | This replays reduced decision logic. It is not a native scanner run or a deployed scan. |

The [PriorSeal control](../controls/priorseal-tampered-intent.mjs) changes `callTarget` and the corresponding observed target
while keeping the original declared hashes and signature. A separate recursive
serializer checks the producer's sorted compact JSON rule for the ASCII fixture.
It excludes the nested `intentHash` from the preimage. This does not qualify that
rule as general JCS. The original producer result stays a positive control.

Producer-supplied inputs, a reader written by another author and a run operated
by another party are different claims. A maintainer who merges a candidate suite
adopts those tests in that host. None of these actions establishes an observed
production effect, protocol adoption, customer pilot or commercial agreement.

The owned installed run uses the same Probity author and operator. Replays of
third-party fixtures retain their source authors and identify the replay operator
separately. No source reader receives credit for an observation it did not collect.

The source pin check reads the original repository license files. It records MIT
for the PriorSeal, Frequency and scanner sources, and Apache-2.0 for federation-port.
This directory follows Atlas's Apache-2.0 license. No third-party implementation
was substituted for the owned reader.
