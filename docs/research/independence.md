# Independent implementation history

Five first-party implementations shared one author's reading: the Go core, Python rail and three consumer rails in two stacks. Their differential checks catch transcription drift. A from-spec implementation by another author can expose a shared interpretation error.

This history records the independent Rust verifier [Rul1an/aee-checker](https://github.com/Rul1an/aee-checker/tree/ef8438c4d6651090f0298516663fc03febe432ac), with its own I-JSON parser, RFC 8785 serializer, RFC 6962 root, run binding and Ed25519 tier. The historical figures below retain the labels and partitions published in the [README snapshot at bbdef583](https://github.com/probityai/agent-evidence-vectors/blob/bbdef583c9241138e5c2b5d872bc77f7f539e9ac/README.md#on-independence).

## Recorded runs

| Historical corpus label | Result | Run character |
| --- | --- | --- |
| suiteRevision 1 | 125/125 | Blind first full run; no vector-driven fixes |
| suiteRevision 2 | Unchanged build 132/138; directed update 138/138 | Followed a specification diff |
| suiteRevision 3 | 140/140 | Unchanged build; its rule predated the two new vectors |
| suiteRevision 5 | 149/149 | Adopted the normative nesting bound of 128 and container-branch depth counting in aee-checker#3 |
| suiteRevision 6 | 153/153: accepts 36/36, rejects 117/117; unchanged revision-5 build 151/153 | Directed RFC 7493 Section 2.1 noncharacter fix, aee-checker#4, 2026-07-28 |
| suiteRevision 22, v0.7 blind | 179/232: accepts 8/54, rejects 169/176, indeterminate 2/2 in suiteRevision 22 | Pinned text only; original build unrecoverable |
| suiteRevision 22, v0.7 directed | 232/232: accepts 54/54, rejects 176/176, indeterminate 2/2 in suiteRevision 22 | Spec diff plus an adversarial implementation review |
| Historical suiteRevision-25 posting, 2026-08-12 | 250/250: accepts 55/55, rejects 193/193, indeterminate 2/2 in historical suiteRevision 25; reason parity 69/193 | Directed, at suite `97ba4ff`, spec digest `759d2383` |
| suiteRevision 28; checker index label 27 | 272/272 | Frozen build before the corpus moved; see [external record](external-records.md) |

The 125/125, 140/140 and blind 179/232 runs bear on unaided interpretation. Other full scores followed specification changes or directed review. Retain that distinction when citing them.

The author described the directed suiteRevision 6 run as follows:

> This one is directed, and more so than revision 2 was: the rule was written and the vectors named before this checker ran, so what it demonstrates is that the corrected rule is implementable from the text, not that an independent reader found it.

His historical suiteRevision 25 posting opened with:

> Repinned and implemented first, then measured your open question.

### Blind v0.7 mismatch account

The posted blind report supports this partition of its 53 mismatches:

| Message observed | Count |
| --- | --- |
| Derived run binding disagreed with `aeeRunBinding` | 42 |
| Returned valid without a reason | 7 |
| Carried `pass_indirect`, recomputed `pass` | 4 |

An earlier per-fix attribution was withdrawn: no bisection could be performed because the blind build had never been committed separately. Its source digest is explicitly null, with `sourceUnrecoverable`, and 179/232 is not independently reproducible, including by its author. The later build's digest must not be assigned to that run.

No reason-parity figure was published for that blind account. The checker emitted prose; two prose-to-code mappings disagreed, with the ambiguity retained as a runnable script.

## Reproduction pins

Use the [checker's pinned source index](https://github.com/Rul1an/aee-checker/blob/ef8438c4d6651090f0298516663fc03febe432ac/reports/INDEX.json) for report hashes, checker digests, commits and rewritten suite pins. Its record labels also differ from the older README account: the 250-vector pin is indexed as revision 26 and the 272-vector pin as revision 27.

| Record | Pin information |
| --- | --- |
| Revision 6 | Checker source digest starts `1c3e2e78`; rewritten suite commit is `6aa7c607ddc73fa7cb2f61814ab2932087fc4988`. The index retains the original pre-rewrite ID separately and says the 153 vector bytes of suiteRevision 6 are identical. |
| Revision 22 blind | Null checker digest; source unrecoverable. Report fields and limitations remain attached to the result. |
| Revision 22 directed | Suite `4cd65a16`; the source index carries the directed build's checker digest. |
| 250-vector directed record | Suite `97ba4ff`, spec digest `759d2383`; the index now includes a checker source digest and reachable commit. |
| 272-vector directed record | Suite `e98de66d`, unchanged checker digest from the 250-vector record; the index marks this as its continuously verified record. |

The earlier README's revision-6 CI description and missing-digest descriptions for directed runs are historical. The pinned index supplies the current reproduction metadata without turning an old run into a new measurement.

## Corpus revisions without a posted score

The historical README retained this scoping sentence:

> It has not been run against suiteRevision 4, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 23, 24, 26, 27, 29, 30 or 31, so this suite publishes no score for it at any of them.

That sentence uses the suite's historical labels; the linked source index uses its own labels and source pins. Requirements present in a later measured population do not create a run record for each earlier population.

| Revision group | Relevant difference |
| --- | --- |
| suiteRevision 4 | Same 140 vector bytes and verdicts as revision 3; new normative encoding and depth text was not exercised. The checker still used 256 until revision 5 adopted 128. |
| 7 through 21 | Their added requirements appear in the measured revision-22 corpus: signatures, attack floor, timestamp profile, v2 run binding, fourth result value and posture vocabulary. Revision 13 changed five results, so a later pass cannot be assigned backward. |
| 23 and 24 | Revision 23 added sixteen rejects and a second condition on a seventeenth; revision 24 moved vendored text without changing vectors. |
| 26 and 27 in the historical account | Revision 26 added eight boundary vectors; revision 27 pinned extra reference emissions without changing vector files. Their vectors were present in the measured revision-28 population. |
| 29 | Added three rejects for absent, null and empty predicates after that run. |

## Findings from the outside reader

| Finding | Resolution |
| --- | --- |
| Five first-party rails selected depth 128; the independent checker selected 256 under the same text. The 127 intervening depths exposed different validity decisions. | The specification made 128 normative. |
| Go counted depth per parsed child, admitting an empty-container leaf one level beyond the bound accepted by Python. | Fixed and covered by a boundary-vector pair. |

To test another implementation, follow the [external-verifier contract](../reference/verifier-contract.md). A reference CLI demonstration is:

```sh
GOWORK=off go build -o aee-verify ./cmd/aee-verify
python3 packaging/run_vectors.py --verifier "$PWD/aee-verify -json"
```

The [comparison rules](../reference/verifier-contract.md#comparison-rules) separate normative conformance, reason parity and the run's exit status.
