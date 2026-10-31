---
title: "When the call changes, check its approval again"
subtitle: "Keep a later state change separate from the original action"
description: "Compare a rewritten agent request with a later changed file, then contribute a reader or retained run."
toc: false
---

An agent gets permission to write a file, then changes the path before sending
the call. It needs approval for the call it actually sends.

Now take a different case: the approved write completes, and someone changes
the file later. That later change needs its own observation. It should not
erase the earlier matching result.

[Read the shared case table](examples/request-effect-join/CASE-TABLE.md).
It follows `giskard09`'s [selected execution-join contract](https://github.com/giskard09/argentum-core/blob/f4d989052bb3a61691b1b156cd6dd655793fea4f/docs/spec/execution-join-ref-v1.md)
and keeps the proposed later-state outcome separate from its existing digest checks.

Bring a reader, the producer's vectors, or a retained file-effect run to the
[Lab thread](https://github.com/probityai/agent-evidence-vectors/issues/352).
Another project can run the same cases and compare outcomes directly with you.
We maintain the case table and credit the case, code and runs separately.

The [SQL example](approved-sql.html) gives you a runnable comparison of a
matching recorded commit and a later state difference. The execution-join
table is a proposed experiment; its native verifier run is a separate contribution.

<details>
<summary>Inspect the exact contract and target-coverage boundaries</summary>

The case table pins the producer contract and distinguishes
`EFFECTIVE_CALL_REBINDING_FAILED`, `DIGEST_MISMATCH`, and the proposed
`POST_COMMIT_DIVERGENCE` observation. It also keeps declared, hashed-action
and executor-configured targets separate. Configuration and a matching
declared/action relationship do not establish where a request actually went.

[Claim P-85](claims.html) records this proposed source comparison and its limits.

</details>
