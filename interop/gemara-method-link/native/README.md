# Native Gemara schema validation

These author-produced reports validate documents against exact upstream CUE
packages. They complement the recorded method-link reader. The original cases,
manifest, reader, and reader reports retain their published bytes.

[MANIFEST.json](MANIFEST.json) pins the native sources, migration inputs, tool,
and [expected schema verdicts](EXPECTED.json). The complete upstream package
is assembled from its pinned files. Identical files are shared between the
profiles; each profile uses its own `evaluationlog.cue`. The package has no
external CUE module imports. Original Apache-2.0 headers and the corpus
[license](../LICENSE) cover the additional Gemara sources.

The native command is `cue vet -c -d '#Policy' . document.json` for each bound
Policy document and `cue vet -c -d '#EvaluationLog' . document.json` for each
log. Documents are checked separately. This does not unify a log with a policy
or resolve a mapping reference. See the official [vet reference](https://cuelang.org/docs/reference/command/cue-help-vet/)
and [data validation guide](https://cuelang.org/docs/concept/how-cue-enables-data-validation/).

The tool is the official CUE v0.15.4 Linux AMD64 release, built with Go 1.25.6.
Its archive and executable SHA-256 values are recorded in the manifest.
The version matches the pinned upstream [schema-test dependency](https://github.com/jpower432/sci/blob/1f66294aaadb82e1188e9ce0475bf9f60f09fe2e/test/go.mod).
The CUE module language version remains v0.15.1. A missing tool, different
executable, compile failure, or unrelated diagnostic fails the gate.

## Recorded profile

[historical-result.json](historical-result.json) validates the original bundles
against [the recorded draft revision](https://github.com/jpower432/sci/tree/1f66294aaadb82e1188e9ce0475bf9f60f09fe2e).
Its totals derive from every log and bound Policy document, including the
documents inside cases rejected by the relationship reader.

The rejected logs are `plan-without-inputs`, `inputs-without-plan`, and
`duplicate-assessment`. Their exact diagnostic paths are retained in the
expectation and report files. The native schema accepts unknown and ambiguous
method or plan references, an empty method ID, declared executor mismatches,
and opposite reported outcomes. These remain relationship-reader questions.

## Pinned execution-context migration snapshot

[current-result.json](current-result.json) uses [a separately pinned draft revision](https://github.com/jpower432/sci/tree/bdc3a4029475c1648aede1a17b761175d121baad).
It records the breaking rename from `plan-inputs` to `execution-context` without
rewriting the original corpus or claiming a migrated relationship reader.
The sample inputs derive from the original `matched-method` and
`same-name-other-executor-id` bundles; each input has its own digest.

| Current sample | Native log verdict |
| --- | --- |
| Execution names a method under a plan | Accept |
| A plan is cited but execution omits the method | Reject at `execution-context.method-id` |
| Execution names a method without a plan | Accept |
| Empty execution settings without a plan | Accept |
| Explicit executor differs from the plan | Accept |
| Distinct plan references share local IDs and method | Reject at `_uniqueAssessments` |

Acceptance preserves a mismatch as an event; it does not establish plan
conformance. These draft fields have not been adopted. Native validation is
author-produced and does not constitute an independently written reader.

## Identity comparison

[identity-result.json](identity-result.json) records a historical input whose
assessments cite different plan reference IDs with the same local entry and
method IDs. Both bound Policy documents validate. The historical native log
rejects this input while the recorded reader returns no shape error and
retains both matched rows. The current sample reproduces the same native
duplicate-key rejection. This report exposes the disagreement; it selects no
cross-policy identity rule on behalf of Gemara.

Neither profile authenticates actor IDs, proves execution, validates method
reliability under [Gemara #496](https://github.com/gemaraproj/gemara/issues/496),
or selects a conflict winner under [Gemara #482](https://github.com/gemaraproj/gemara/pull/482).

## Reproduce

Download and extract the exact release asset named in the manifest, then run
from the corpus directory with its verified executable path:

```sh
python native_cue.py --cue /path/to/cue --output-dir native/.build
GEMARA_CUE_BINARY=/path/to/cue python -m pytest test_native_cue.py -q
```

The [active workflow](../../../.github/workflows/ci.yml) (job `gemara_method_link`)
verifies the archive before extracting only the executable, then verifies its
digest and runtime. It reruns native and original reader checks and compares
each generated native report byte-for-byte. Positive upstream fixtures prevent
a broken package from masquerading as expected rejection. Controls cover
source/input tampering, lost case coverage, an accept-all native result,
missing or substituted tools, compile errors, and unrelated diagnostics.
