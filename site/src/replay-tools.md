---
title: "Run the APS and PriorSeal replay"
description: "Use the pinned producer tools, declare the caller and retain the commands, source hashes and results."
---

## Choose the procedure

The [complete source-replay procedure](https://github.com/probityai/agent-evidence/blob/main/site/experiments/aps-priorseal-source-replay/RUN.md)
gives the producer commits, required tools and both executable commands.
Select and retain a published Atlas commit before running it.
It also supports copied tools outside an Atlas checkout: retain the entrypoint,
its `runner.mjs` helper and, for the replay, the unchanged `recorded.json` baseline.
Use all files from the same selected Atlas commit.

The replay runs the pinned Frequency adapter directly.
The separate wrapper check asks whether a zero exit also produced a new report.
These are different checks. Neither authenticates a real operator or establishes
a live action, production use or an independently operated witness.

## Declare who ran it

Both entrypoints require one `--runner` before their four path arguments:

```sh
node experiments/aps-priorseal-source-replay/run.mjs \
  --runner https://github.com/OWNER/REPOSITORY \
  CAPSULE APS_OWNER PRIORSEAL_COPY NEW_OUTPUT
```

Replace the caller and paths with your selected inputs.
The complete procedure gives the corresponding wrapper command.
The tools refuse an omitted, repeated or unknown option before inspecting the
producer checkouts or creating output. They never infer the caller from a
publisher or an earlier record.

New v2 records retain `scope.runner.identity` and `source: "caller-declared"`.
The declaration is not an authenticated identity.
`harness.files` binds the entrypoint and helper bytes read at invocation.
Those hashes do not attest the publisher or the runtime.

## Keep the actual outputs

Keep the generated `receipt.json` or `record.json`, its child command metadata
and raw stdout and stderr together. Process-file paths are relative to their
record's directory. The record binds those files by size and SHA-256.
A spawn or capture error is incomplete and refuses a successful
record. Retain the source selection and environment with your capture.

The CI artifact keeps `result/receipt.json` and `contract-result/record.json`
with their sibling logs. The curated controls are in `caller-controls/public-results/`.
Their manifest declares that base relative to its own directory and binds each
selected file by size and SHA-256. Follow those declared paths to check the artifact.

The wrapper's `meetsRunContract` is true only when its actual and retained exits
are zero and a previously absent report path exists after execution.
It does not establish that the report is valid or that Probity admitted it.
The procedure leaves the original producer outcomes and their stated limits unchanged.

## Read the existing evidence

The [pilot status](pilot.html) distinguishes technical replay from a formal pilot.
The [retained-run browser](runs.html) presents existing registered claims and
their original artifacts. The [claim ledger](claims.html) records this interface
and its re-derive commands. Historical records keep their original schemas and
bytes; a new caller declaration does not change their results.
