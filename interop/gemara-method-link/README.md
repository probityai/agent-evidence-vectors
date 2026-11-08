# Gemara plan and method links

An author-produced draft corpus for the shape proposed in
[Gemara #506](https://github.com/gemaraproj/gemara/pull/506), pinned at
`1f66294aaadb82e1188e9ce0475bf9f60f09fe2e`. This proposal has not been
adopted or run by an independent reader.

The 20 cases use complete Policy and EvaluationLog documents derived from the
upstream fixtures. They exercise `plan-inputs.method-id` in the cited plan,
unknown and ambiguous references, a method that exists only in another plan,
declared executor mismatches, executor omission, and two methods reporting
opposite outcomes. They also pin the plan/input pairing and duplicate-assessment
preconditions exercised here. Source bytes and case bytes are SHA-256 pinned in
`MANIFEST.json`.

Run the bundled reader with Python 3.11 or later:

```sh
python method_link.py
python -m pip install -r requirements-test.txt
python -m pytest test_method_link.py -q
```

The dated author-produced measurements are in [RUN.md](RUN.md). The pytest
checks cover Hypothesis properties, source and fixture tampering, path traversal,
reader failure, and an accept-all negative control. The active
[workflow](../../.github/workflows/ci.yml) (job `gemara_method_link`) reruns the checks,
verifies the source and input pins, and compares reader and control reports
with the checked-in records. The accept-all command must fail:

```sh
python method_link.py --adapter "python controls/accept_all.py"
```

An external reader consumes only the input bundle as JSON on stdin and returns
the same result shape as the expected object in each case. Expected answers are
not sent to the command. The command is parsed into arguments; no shell runs:

```sh
python method_link.py --adapter "python another_reader.py"
```

The bundled reader can answer that contract with `python method_link.py --stdin`.
Running it through the contract is a self-adapter check, not an independent run.

The reader preserves an executor mismatch as an event and reports the mismatch
separately. It compares declared IDs, not display names. An omitted executor
denotes `metadata.author`, as #506 proposes. A conflict preserves both reported
results; this profile selects no winner. Method validation under
[Gemara #496](https://github.com/gemaraproj/gemara/issues/496) and conflict
resolution under [Gemara #482](https://github.com/gemaraproj/gemara/pull/482)
remain separate.

The output labels are proposed reader-contract labels. They are not Gemara
schema verdicts. Separately recorded [native CUE verdicts](native/README.md)
cover the original schema revision and a versioned migration sample. The caller explicitly
binds mapping-reference IDs to policy documents; the reader performs no remote
lookup or version discovery. Requirement comparison covers the local entry ID
within the fixture's catalog. Executor IDs are not authenticated, and agreement
of records establishes neither actual execution nor independent observation.
The duplicate key includes full reference mappings; both pinned native schema
revisions use the local entry IDs. The native identity report exposes their
disagreement on distinct plan reference IDs. Cross-policy identity needs a
maintainer decision.

The original upstream schema and fixture sources are retained under `sources/`
with their immutable URLs in the manifest. Gemara's sources use Apache-2.0.

The package includes the exact upstream Apache-2.0 `LICENSE` pinned at both source revisions. Original source copyright/SPDX headers are retained. The manifest hashes the license text; neither pinned upstream root listing returned a NOTICE file.
