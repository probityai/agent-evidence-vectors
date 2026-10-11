# MCP tool calls as signed receipts

Worked examples of the [Observed Effect](../../spec/predicates/observed-effect.md)
predicate applied to MCP tool calls: one signed record per call, sealed by an
observer below the call, with its commitment to the authority and the starting
state signed before the call opens. Each record verifies offline, from its own
bytes, with the reference verifier in
[`vectors-observed-effect/check_vectors.py`](../../vectors-observed-effect/check_vectors.py).

```sh
uv run --extra generators python examples/mcp-receipts/gen_examples.py    # rebuild, byte-identical
uv run --extra generators python examples/mcp-receipts/check_examples.py  # verify and link
```

## The two topologies

**[`chain/`](chain/)** is a sequential call chain: read a config, write
`main.py`, write `handler.py`. Each call's `interval.beforeRoot` is the previous
call's `interval.afterRoot`, so the session is the chain of records. A dropped,
inserted or reordered call breaks the chain where it happened, and the checker
proves that with a reordered control that must fail to link.

**[`fanout/`](fanout/)** is a parallel fan-out: one dispatch, each call run in
its own fork of one parent state. Every branch carries the same `beforeRoot` and
its own `intervalId`. A propagated thread id is exactly what breaks here. These
records do not need one: the commitment preimage includes `intervalId`, so the
commitment signed for one branch is refused on a sibling with
`commitment-digest-mismatch` (attack A9 in the predicate), and the checker runs
that replay as its second control.

## Where the intent lives

Every record carries the same `authorityDigest`: the RFC 8785 digest of
[`authority.json`](authority.json), which names the originating intent, the
requester, the executor, the grant and the tools. That digest is inside
`observation.priorCommitment`, which the observer signs before `openedAt`. So
the intent a call ran under, and who asked versus who acted, is fixed before the
call starts. It survives fan-out, retries and hops as signed content. It is not
a header that every hop has to forward.

## What these records do not claim

The keys are the corpus's published test keys and the state roots are labelled
digests, so these are worked examples of the record shape rather than captures of
a live run. Each record's `doesNotAssert` list states the rest.
