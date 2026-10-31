---
title: "Did the database write match its approval?"
subtitle: "Compare the request, execution record and audit event"
description: "Run an approved SQL example, then help connect a real database audit pair or another reader."
toc: false
---

An agent gets approval to update a database. The application reports success.
Later, someone reads a different value. Did the approved write happen, or did
another write change it afterwards?

[Try the reader and examples](examples/approved-sql/README.md). They compare the
approved SQL and parameters with the application record and audit projection,
including the database, schema, principal and transaction outcome. A later state
change stays separate from an earlier matching commit.

Cho HyunJong brought this case to the [Lab thread](https://github.com/probityai/agent-evidence/issues/24#issuecomment-6247269344).
The examples are ours. A real Tadpole approval and database audit pair is the
next contribution; another project can bring a reader and compare results.

Want to help? Bring a shareable pair, run the examples with another reader, or
pick a check to keep in your own CI. [Join the case in the Lab](https://github.com/probityai/agent-evidence/issues/24).
We maintain the comparison code and credit the case, code and runs separately.

<details>
<summary>Run it and inspect the exact fields, source and results</summary>

The illustration was qualified on 9 October with 16 author-created fixtures and 56 passing tests.
A 17th fixture, added on 24 October, pins a refused approval with no matching audit record; 57 tests pass.
It compares supplied records; it does not authenticate their source or verify
that an audit collection is complete.

From the Atlas checkout:

```sh
cd examples/approved-sql
uv sync --frozen --group dev
.venv/bin/python -m sql_illustration.check fixtures/matching-commit-later-change.json
.venv/bin/python scripts/qualify.py
```

The first command reports `recorded_commit_matches` alongside
`supplied_state_differs`. Changed SQL, parameters, target or identity produce
separate failures. Missing or ambiguous audit evidence keeps its own outcome.

Read the [input contract](examples/approved-sql/docs/INPUT-CONTRACT.md),
[source map](examples/approved-sql/SOURCE-MAP.md),
[design decisions](examples/approved-sql/docs/architecture/DESIGN_DECISIONS.md)
and [retained check record](examples/approved-sql/QUALIFICATION.json).
[Claims P-83, P-84 and P-114](claims.html) bind the source and measured scope.

</details>
