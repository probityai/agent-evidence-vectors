# Conformance vectors (ANCHORS stream, `anchors-verify-v0.4`)

Every member of this suite in one table, accepted and rejected alike.
Ground truth: `spec-vendored/anchors-verify-44c40ba.md`, the contract text bundled with the pinned tag
`anchors-verify-v0.4` of `aos-standard/catalog` at `44c40ba`, whose sha256
`MANIFEST.json` pins as `specDigest`.

This corpus is 34 vectors, of which 13 a conformant verifier must
not fail closed on and 21 it must reject.

**What this corpus certifies against, which is not the vendored text alone.**
Two conditions are required by the contract as vendored, and their reject
members are rejectable under it as written. The other eight are corrections
this corpus proposes: the vendored text leaves those cases open, which is why
the correction is worth writing down at all. A row's `basis` column says which
it is, `MANIFEST.json` carries the same field per member, and any table or
count quoted out of this directory carries this sentence with it. Reading a
`proposed` row as a conformance failure against the published text overstates
what the published text requires. Where upstream has since made the same change
the condition names the tag it landed at, which is a fact about their history
rather than a licence to restate the row as vendored.

**What a row states.** An `accept` row states that a conformant verifier does
not fail closed on those bytes, and names the outcome the contract's own table
assigns them. A `reject` row states that a conformant verifier fails closed,
and names the reason it stops. The reason is the load-bearing half. A verifier
that reaches the right verdict from a guard that fired before it evaluated the
property has not evaluated the property, and the verdict column cannot tell
you which happened.

**The platform bytes are pinned.** A verifier for this format reads the witness
platform over the network. Every member therefore carries `witness/<id>.json`,
which holds the bytes the platform serves for each commit the member names,
the bytes of the default branch, and, per commit, whether it is reachable from
that branch. Reachability is a fact about the platform rather than about the
bytes, so it is carried rather than derived. `run_verifier.py` refuses to run
a verifier that reaches for a socket.

**Identifiers name the bytes.** Each identifier is a digest of the member's own
three files. There is no directory per verdict and no prefix per verdict; the
expectation lives in `MANIFEST.json`. A verifier could otherwise certify
against this corpus without opening a stream.

Regenerate byte-identically: `python3 gen_vectors.py`.
Self-check: `aee-verify vectors-anchor-stream/` from the repository root.
Run a verifier: `python3 run_verifier.py --verifier <path-to-anchors_verify.py>`.

## Conditions

| id | basis | what it requires |
|---|---|---|
| `ans-c-1` | as-vendored | A line digest covers the stored bytes of that line. Two streams whose bytes differ inside an attested prefix do not verify identically. Already required by the vendored text: hashes cover the full stored line including the trailing newline byte, and upstream made the same change at `anchors-verify-v0.5`. |
| `ans-c-2` | as-vendored | A stream whose final line carries no terminator is a different stream from one whose final line carries a terminator. Already required by the same sentence of the vendored text, applied to the line that has no trailing newline byte. |
| `ans-c-3` | proposed | Every presented line has a sidecar entry. A line with no entry has not been verified, and the verdict says so. Left open by the vendored truncation rule fires only when the sidecar is longer than the stream, so a shorter one is not refused by the text as written. |
| `ans-c-4` | proposed | The success outcome is reachable by an honest stream. An outcome table does not document a verdict no input can produce. Left open by the vendored table documents the success verdict and the predicate beside it makes that verdict unreachable, so the correction is to the predicate, and upstream made the same change at `anchors-verify-v0.7`. |
| `ans-c-5` | proposed | A named witness commit is reachable from the pinned repository's default-branch history, not merely fetchable under its path. Left open by the vendored text pins a repository name and says nothing about whose history a commit came from, and upstream made the same change at `anchors-verify-v0.7`. |
| `ans-c-6` | proposed | A row carrying a recognised boundary event carries no record-shaped fields. A row that is both is malformed. Left open by the vendored text defines a record by the absence of an event and leaves a row that is both unresolved, and upstream made the same change at `anchors-verify-v0.9`. |
| `ans-c-7` | proposed | An unrecognised rule_version fails closed. Not knowing a rule set is not the same as that rule set being satisfied. Left open by the vendored text names three rule sets and does not say what a verifier does with a fourth, and upstream made the same change at `anchors-verify-v0.8`. |
| `ans-c-8` | proposed | A field the format declares an integer rejects a JSON boolean. Python's bool-is- int identity is not a property of the wire format. Left open by the vendored text calls these fields counts and lengths and pins no JSON type for them, and upstream made the same change at `anchors-verify-v0.9`. |
| `ans-c-9` | proposed | A position binding names the repository its witness lives in, and the pinned trust anchor is compared against that name. Left open by the vendored text says a stream naming a different repository fails closed and does not say what a stream naming none does. |
| `ans-c-10` | proposed | The verdict is a function of the pinned artifact. A run described as tag-fixed does not read a moving branch. Left open by the vendored text calls the run tag-fixed and reproducible while the implementation reads the default branch during it. |

## Vectors

| id | kind | conditions | expected outcome | exit | stop reason |
|---|---|---|---|---|---|
| `v0e6e29013cfcb97c` | reject | ans-c-1 | `VERIFY FAILED` | 1 | `digest-mismatch` |
| `v0e89189941e44d8e` | accept | ans-c-4 | `VERIFY PARTIAL` | 3 | none |
| `v0ef2243ce9ba64f6` | reject | ans-c-1 | `VERIFY FAILED` | 1 | `digest-mismatch` |
| `v1247b05a03902477` | reject | ans-c-5 | `VERIFY FAILED` | 1 | `witness-unreachable` |
| `v128381d395659cb6` | reject | ans-c-10 | `VERIFY FAILED` | 1 | `truncation` |
| `v1b748575d8a7ee95` | accept | ans-c-7 | `VERIFY PARTIAL` | 3 | none |
| `v25a148d9df730b88` | reject | ans-c-2 | `VERIFY FAILED` | 1 | `digest-mismatch` |
| `v27ec0ed3abec3bed` | reject | ans-c-1 | `VERIFY FAILED` | 1 | `digest-mismatch` |
| `v30bb2edf2b9f23ba` | accept | ans-c-7 | `VERIFY PARTIAL` | 3 | none |
| `v3c142a4f8828f505` | accept | ans-c-2 | `VERIFY PARTIAL` | 3 | none |
| `v3e2e8c8036db8c91` | accept | ans-c-4 | `VERIFY OK` | 0 | none |
| `v415ba6da9df54f96` | accept | ans-c-2 | `VERIFY PARTIAL` | 3 | none |
| `v4598881bb94db9a9` | reject | ans-c-2 | `VERIFY FAILED` | 1 | `digest-mismatch` |
| `v4f206ff8ed18be87` | accept | ans-c-1 | `VERIFY PARTIAL` | 3 | none |
| `v570c22575790427c` | reject | ans-c-1 | `VERIFY FAILED` | 1 | `digest-mismatch` |
| `v7199fe21ece3c6b2` | reject | ans-c-7 | `VERIFY FAILED` | 1 | `unknown-rule-version` |
| `v8c0edba09c428917` | reject | ans-c-3 | `VERIFY FAILED` | 1 | `sidecar-coverage` |
| `v8cfc723dce226033` | reject | ans-c-1 | `VERIFY FAILED` | 1 | `digest-mismatch` |
| `vb519de5288c2a572` | accept | ans-c-5 | `VERIFY PARTIAL` | 3 | none |
| `vba949c40114507b1` | reject | ans-c-7 | `VERIFY FAILED` | 1 | `unknown-rule-version` |
| `vbc642e97495a754d` | accept | ans-c-9 | `VERIFY PARTIAL` | 3 | none |
| `vbf8a4048eba3d662` | reject | ans-c-1 | `VERIFY FAILED` | 1 | `digest-mismatch` |
| `vca6a55637cd0742d` | reject | ans-c-6 | `VERIFY FAILED` | 1 | `malformed-row` |
| `vcdb22e90c0812237` | reject | ans-c-8 | `VERIFY FAILED` | 1 | `invalid-byte-length` |
| `vcec4ba461275d0b4` | reject | ans-c-1 | `VERIFY FAILED` | 1 | `digest-mismatch` |
| `vd6eecc03efb27ebd` | reject | ans-c-3 | `VERIFY FAILED` | 1 | `sidecar-coverage` |
| `vd7195c86129b959f` | accept | ans-c-8 | `VERIFY PARTIAL` | 3 | none |
| `ve28432cb7adcdc6b` | accept | ans-c-6 | `VERIFY PARTIAL` | 3 | none |
| `vf4bccf922ed33749` | reject | ans-c-1 | `VERIFY FAILED` | 1 | `digest-mismatch` |
| `vf8ef32f6294cea06` | reject | ans-c-1 | `VERIFY FAILED` | 1 | `digest-mismatch` |
| `vf9c8df1aeafd69f7` | accept | ans-c-3 | `VERIFY PARTIAL` | 3 | none |
| `vfc54e61742cea5f5` | accept | ans-c-10 | `VERIFY PARTIAL` | 3 | none |
| `vfccf46c02cc12618` | reject | ans-c-9 | `VERIFY FAILED` | 1 | `binding-repo-absent` |
| `vffcb99f9cab7c8a9` | reject | ans-c-8 | `VERIFY FAILED` | 1 | `invalid-line-count` |
