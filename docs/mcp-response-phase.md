# The response phase sees every completion

Status: proposal, with a conformance corpus. The two rules below are measured
by `vectors-mcp-response-phase/`, so they are not rules anyone has to take on
trust.

## The gap

The MCP interceptors proposal (`modelcontextprotocol/experimental-ext-interceptors`,
`docs/sep.md`, vendored at `vectors-mcp-response-phase/spec-vendored/`) defines a
Lifecycle Event as "a specific moment when a context operation is initiated
(request phase) or completed (response phase)", and an interceptor hooked on
`phase: "response"` is invoked at that moment. It does not say what the
response-phase payload is when the operation completes with a JSON-RPC error
object instead of a `result`.

That silence has a cost. JSON-RPC 2.0, section 5, makes the error object a
Response: a server answering a call replies with a Response object carrying
exactly one of `result` or `error`. An upstream MCP server can put any text in
`error.message` and any JSON in `error.data`, and the caller's agent reads both.
A gateway whose response phase inspects `result` and forwards `error` untouched
has a policy with a hole in it the size of the error channel, and a validator
configured to refuse every response still lets every upstream error through.

The corpus is written so that a gateway of that shape fails exactly the members
about error frames and passes every member about results, which is what lets it
serve as that gateway's regression test.

## The rules

**MRP-R-001.** An interceptor hooked on the response phase of an event MUST be
invoked when an operation of that event completes, whether the completion is a
JSON-RPC `result` or a JSON-RPC `error` object. The payload it receives MUST let
it tell the two apart and MUST carry the error's `code`, `message` and `data`
members as the upstream sent them.

**MRP-R-002.** A response-phase decision applies to the completion it was
invoked on. When a validator fails the completion, the caller MUST NOT receive
any member of the upstream completion, result or error. When a mutator replaces
the payload, the caller MUST receive the replacement, and a completion that
arrived as an error MUST leave as an error.

MCP reports a tool's own failure inside `result` with `isError: true`, and that
case is already a `result`. It is in the corpus as a control: a gateway that
inspects results sees it today, and a fix for error objects must not stop seeing
it.

## What is out of scope

A transport failure between the gateway and the upstream produces no upstream
completion, so no upstream bytes reach the caller through it and MRP-R-001 does
not govern it. A gateway that turns a transport failure into an error whose
message quotes the upstream's reply has made that reply a completion, and then
it is in scope. Notifications and server-initiated requests are not completions
of the caller's operation and are not covered here.

## How a gateway is tested

The adapter contract is in `vectors-mcp-response-phase/README.md`. A gateway's
CI supplies one executable that stands the gateway up with a response-phase
policy, answers the member's request from a stub upstream with the member's
completion, and prints one line of JSON saying whether the policy was invoked
and what the caller received. The harness does the comparison.
