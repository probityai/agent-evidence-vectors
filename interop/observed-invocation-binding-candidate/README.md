# Observed Effect call binding candidate

Signed cases for the optional `predicate.invocationBinding` member of the
Observed Effect predicate, version 0.9.0. The member names the call an interval
answers: SHA-256 over the RFC 8785 bytes of `{"method": ..., "params": ...}`
from the JSON-RPC request, with the request's `id` and `jsonrpc` excluded. The
value is the same binding the `invocation_axes` corpus pins, written as bare hex.

Every case is built from the released baseline member
`vectors-observed-effect/statements/v1c6fdd82db5229e4.json` and the pinned request
`packaging/agent_evidence_vectors/invocation_axes/corpus/invocation.json`, signed
with the corpus's published test key. No released member changes.

| Case | Consumer pin | Verdict |
| --- | --- | --- |
| `legacy-absent`, `present-unrequested` | none | valid |
| `required-match` | the pinned request | valid |
| `request-id-differs-match` | the request with another JSON-RPC id | valid |
| `params-member-reordered-match` | the request with argument members reordered | valid |
| `params-value-changed-mismatch` | the request with one argument value changed | invalid, `invocation-binding-mismatch` |
| `required-absent` | the pinned request, member absent | invalid, `invocation-binding-required` |
| `required-mismatch` | the pinned request, member names another call | invalid, `invocation-binding-mismatch` |
| `invalid-consumer-pin` | not 64 lowercase hex | invalid, `invocation-binding-policy-invalid` |
| shape and value cases, including `tagged-value` (`sha256:<hex>`) | none | malformed |
| `binding-replaces-after-root`, `binding-is-second-subject` | the pinned request | malformed, subject rules |
| `unsigned-binding-change` | none | invalid, `envelope-signature-invalid` |

Rebuild with `python interop/observed-invocation-binding-candidate/generate.py`;
CI checks the committed files are what it writes. Run the cases with
`python -m pytest interop/observed-invocation-binding-candidate/test_invocation_binding.py`
and `go test ./observedeffect -run InvocationBinding`. Both Python readers and
the Go reader must give the same verdict and codes on every case.

What a match establishes: the observer signed that this interval answers that
call. It does not establish that the call was dispatched, that the decision was
correct, or that the binding was committed before the interval opened.
