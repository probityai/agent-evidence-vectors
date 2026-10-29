# MCP response-phase interception

Conformance vectors for a gateway or client that runs interceptors on the
**response phase** of an MCP operation. The question each member asks is whether
the response-phase policy is invoked on the operation's completion at all, and
whether its decision governs what the caller receives.

[![Checked with Probity](https://img.shields.io/badge/checked-with_Probity-0969da?logo=data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAMAAABEpIrGAAAAkFBMVEX8%2B%2Bzr5NPgyrfKyLnSq5Wzo4tWltqRkZI2kPU1kvk1j%2FMwkPgzjfI2jO80jO40jO3MdWOZc1SLblN1aFxxXFJzVDY2i%2B40i%2B00i%2Bw0i%2Bs0ius1iOZAapwugNYtdbUqaq0qV4tkRzJXOB47Oz43JRkjNEYiHBwlFxIfFxMcEg0XEQ0WEAwXDAUWCAEOCQcJAgCa503RAAAB3klEQVR42rWT2ZacIBCGceHYoN240SK2Crig4vL%2BbxfszJyZTmaSm6S4rI9a%2FwK3vxj41wDj5E9AwS%2Foxjn7DmARqgVHCBHyJcBxJeZtEG2Nv4hAGEPXYVumddvWAbFfgJJECDfDukxa63ldmw%2FiCTCEK%2BteFzNbQI%2BbQPwzwKJGjNO2LMacxNqK1wgcNfO2mqfbHMs8NEkeXT8AjurRTKfbMlqOa5vFyc8cZclu4PSvWptlPlOMeb4PsQu78MoYQWFIwKUet0nPZl%2FMki1H3x%2FKd1PVhhdkS2tDgM7m9bR3XX8EXtYde59SSVVXNx2NMwuIbbGl74HUu%2BcFXrArSpXqlVSpGz8sUG%2FjoCej1RHA6ZAgl1SmUvVUQjduEGDIdt0MxuwjCHYNAZSwT1IbhaZ%2BFt7BrUAXbguxnx3gZ9AJVJLal0hKaYv4OShGbu249Z4F4jhQ1PcpTUYLDBF5WxZB9dBB14O%2Bm6eu48QQpjBXIizf113iS9sF0LYxZMD1PODbVvtznu96sGOrWyFEiwQEwHNcC8gaF58UxfG1qiqMqzx2AACJ0i0qXyRXEIwjwnD1SBOYdKJ%2B7vxF1eRUaxGF9ePRVgiX3xxOccdhiK5v6v%2Fysgp2Z%2BR%2F3ebv9gP5RU8tSdZhDwAAAABJRU5ErkJggg%3D%3D)](https://github.com/probityai/probity)

The rules are in `../docs/mcp-response-phase.md`. The specification whose gap
they fill is the MCP interceptors proposal
(`modelcontextprotocol/experimental-ext-interceptors`), vendored in
`spec-vendored/` and pinned by digest in `MANIFEST.json`.

## The gap this measures

The interceptors proposal defines a Lifecycle Event as a moment when an
operation is "initiated (request phase) or completed (response phase)", and a
response-phase interceptor runs at that moment. It does not say what the payload
is when the operation completes with a JSON-RPC error object rather than a
`result`. JSON-RPC 2.0 makes the error object a Response: a completed call
carries exactly one of `result` or `error`. A response phase that inspects
`result` and forwards `error` untouched has a policy with a hole the size of the
error channel, which carries arbitrary `message` text and arbitrary `data`.

The corpus is built so that a gateway with that shape fails exactly the members
about error frames (`mrp-c-2` through `mrp-c-4`) and passes every member about
results, which is what lets it serve as that gateway's regression test.

## Two axes

Each member declares two things, and a reject member differs from its accepting
twin in exactly one of them:

| axis | question |
|---|---|
| `policyInvoked` | did the response-phase policy run on this completion at all |
| `callerReceives` | what completion the caller ends with once the policy has run |

`policyInvoked` is the axis a gateway that skips error frames fails: on such a
gateway the upstream error is delivered unchanged whether or not the policy ran,
so delivery alone cannot separate the two and the invocation flag is what does.

## Every member is synthetic

Each member is one operation shaped after a defect in how a response phase
treats a JSON-RPC error object. No party is named anywhere in this directory.
The `mrp-c-3` payloads carry the shape of the risk — content moved from a result
into an error's `message` and `data` — rather than any real exfiltration.

## The criterion is measured, not asserted

`corpora/mcpresponsephase.go` (run by `aee-verify`) computes what a conformant
response phase must produce for each member's operation — the policy is invoked,
and its decision decides the caller's completion — and compares it with what the
member declares. An accept member must declare the conformant outcome; a reject
member must differ from it on exactly one axis. So the rule is checked against
the corpus rather than stated beside it.

## The adapter contract

A gateway's CI tests itself against this corpus with one executable, invoked as
`<cmd> <member-file>` per member. For each operation the adapter:

1. stands the gateway up with a response-phase policy for `tools/call` that
   returns the member's `operation.policy` decision;
2. answers the member's `operation.request` from a stub upstream with the
   member's `operation.upstreamCompletion`;
3. prints one line of JSON as its last stdout line:
   `{"policyInvoked": <bool>, "callerReceives": {"kind": "result"|"error", ...}}`.

The harness compares that line with the member's `expected` block. The verdict
is in the exit status: zero when every member matched. This is the same
external-implementation shape the repository's other corpora use, and it runs
through the shipped GitHub Action (`action.yml`).

## Running it

```
aee-verify vectors-mcp-response-phase       # self-check, from the repository root
python3 gen_vectors.py                      # regenerate, byte-identically
python3 gen_vectors.py --check              # refuse a tree the generator does not emit
```

## What this corpus does not do

It says nothing about content filtering or prompt-injection detection: the
`mrp-c-3` members test that a policy configured to refuse a response actually
refuses it, not that any particular content should be refused. A transport
failure between the gateway and upstream produces no upstream completion and is
out of scope; a gateway that turns such a failure into an error quoting the
upstream reply has made that reply a completion, and then it is in scope.
