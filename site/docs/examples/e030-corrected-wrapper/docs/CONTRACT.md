# Finite run contract

The CLI requires `--operator`. It accepts no `--runner` alias and guesses no identity.
Identity is a caller declaration, not authentication or independent-operation evidence.
The receipt separately names the vector maintainer and original finder.

Before a run, require the three clean checkouts at the exact commits in `regression.SOURCES`
and the exact wrapper bytes. A new output directory must be outside each checkout.
Injected commands log the actual stages reached. Each attempt retains raw stdout, stderr,
command arguments, actual exit or signal, timestamps, recorded status and comparison.
A timeout terminates this invocation's process group and remains an incomplete run.
A failed start records its error separately from an exit. Neither can pass the comparison.

The consumer first refuses incomplete or nonzero processes, disagreement with the recorded
status, missing pre-run presence observation and any pre-existing report. It separately checks
the report projection: strict UTF-8 JSON,
unique keys, native profile and input pins, the exact claim/result list and summary types,
and the producer-declared generation time against the observed interval. A report must be a
bounded regular file. A symlink, directory, pipe or oversized file refuses.

The comparison is limited to those fields. It does not evaluate signatures, trust-key control,
the producer's full adequacy plan, actual adapter execution, action effects or production use.
The injected native-shaped reports are author-created projections. They are not producer results.

## Generation time and invocation binding

The producer emits `generated_at`, but its native contract has no unique invocation token.
An old declared time or an existing output refuses. A copied valid report with a forged current
time cannot be distinguished by these fields alone. The result therefore keeps run correlation
unknown. No hash, matching timestamp or new file is called proof of execution.

A future producer extension can carry an explicit invocation identifier bound into its report.
That requires a deliberate producer contract decision. This regression does not invent that
field, normalize another identifier into it, or weaken the absence of native correlation.

## Reading the gate

The regression succeeds when every expected adverse control is observed and refused, and the
matching projection passes. That success does not qualify the wrapper's report-content guard.
Its actual bad-report `0`/`PASS` behavior remains in the receipt.
An outside operator can retain this comparison and submit its own source pins, commands and
raw receipts. Outside execution and a kept check are recorded when they actually occur.
