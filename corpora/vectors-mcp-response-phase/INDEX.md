# Conformance vectors (MCP response-phase interception)

Every member of this suite in one table. The subject under test is a gateway or
client that runs interceptors on the RESPONSE phase of an MCP operation, and the
member's question is whether the response-phase policy is invoked on the
operation's completion and whether its decision governs what the caller
receives.

This corpus is 8 vectors, of which 5 a conformant verifier must not
fail closed on and 3 it must reject.

The rules are `../docs/mcp-response-phase.md` and the specification whose gap they fill is
vendored at `spec-vendored/interceptors-sep-b604598.md`, pinned by digest in the manifest.

**Every member is synthetic.** Each is one operation shaped after a defect in
how a response phase treats a JSON-RPC error object. No party is named.

**Two axes.** `policyInvoked` asks whether the response-phase policy ran on this
completion at all; it is the axis a gateway that skips error frames fails.
`caller receives` is the completion kind the caller must end with. A reject
member differs from its accepting twin in exactly one of these.

Regenerate byte-identically: `python3 gen_vectors.py`.
Self-check: `aee-verify vectors-mcp-response-phase/` from the repository root.

## Conditions

| id | what it requires |
|---|---|
| `mrp-c-1` | A response-phase policy on tools/call is invoked on a JSON-RPC result and its decision governs what the caller receives. Because this is the case every implementation already handles, kept as the control that separates a gateway with no response phase from one whose response phase is merely blind to errors. |
| `mrp-c-2` | The policy is invoked on a JSON-RPC error object as well, and the payload lets it read the upstream code, message and data. Because an error object is a completion under JSON-RPC section 5, and a response phase that skips it has a hole the size of the error channel, which carries arbitrary text and arbitrary data. |
| `mrp-c-3` | When the policy fails an error completion, the caller receives none of the upstream error's members. Because a validator configured to refuse every response that still forwards every upstream error verbatim has refused nothing. |
| `mrp-c-4` | When the policy replaces an error completion, the caller receives the replacement and it is still an error. Because a redaction that turns a rejected error into a success, or drops it so the call appears to hang, changes the outcome the caller acts on. |
| `mrp-c-5` | A tool failure reported inside a result with isError true reaches the response phase as the result it is. Because MCP puts a tool's own failure in result.isError, so a fix for JSON-RPC error objects must not start treating that result as one and must not stop seeing it. |

## Vectors

| id | kind | conditions | policy invoked | caller receives |
|---|---|---|---|---|
| `v13e9774048310556` | accept | mrp-c-5 | yes | result |
| `v18929427f9be0de5` | reject | mrp-c-4 | yes | result |
| `v253d3fc574b2a7f1` | accept | mrp-c-3 | yes | error |
| `v57fd254b5473aa54` | reject | mrp-c-2 | no | error |
| `v7cbb52a86b0ff370` | accept | mrp-c-2 | yes | error |
| `v88dd3633e073e5d3` | reject | mrp-c-3 | yes | error |
| `vaf35412b6f540235` | accept | mrp-c-1 | yes | error |
| `vd84f78b45154a02c` | accept | mrp-c-4 | yes | error |
