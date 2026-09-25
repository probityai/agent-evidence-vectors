# BUILD-NOTES: module wiring and verified state

Everything below was compiled and run at the time of writing; this file records
what is needed to reproduce it.

## Module layout (two modules, zero `replace` directives)

| module | path | deps | builds with |
|---|---|---|---|
| core (`./`) | `github.com/probityai/agent-evidence-vectors` | stdlib only (enforced by `aee/imports_test.go`) | plain `go build ./...` / `go test ./...`, no workspace, no network |
| attestor (`./witnessattestor`) | `github.com/probityai/agent-evidence-vectors/witnessattestor` | `github.com/in-toto/go-witness`, `github.com/invopop/jsonschema`, the core | a Go workspace (below) plus module downloads |

No `replace` directive is committed in any `go.mod`, so the cross-module
link is workspace-resolved. The attestor `go.mod` deliberately carries no
`require` line for the core module: in workspace mode the `use` directive
resolves the import, and a `v0.0.0` require line breaks module-graph
loading (a third-party fetch error gets misattributed to the phantom
`v0.0.0` requirement). Once the go-witness dependency is released and the
attestor gains a versioned `require` on the core, `go mod tidy` inside the
attestor module records it.

## Verified build and test state (what was run, in this tree)

Toolchain: `go1.25.5 linux/amd64` for the core. The attestor module builds
under the workspace with toolchain auto-upgrade, because the local
go-witness checkout's `go.mod` declares `go 1.26.1` (a `go.work` whose
`go` line is below that gets rejected, so set the work file's `go`
directive to at least the highest member module's).

The core module is clean end to end: `gofmt -l` clean, `go vet ./...`
clean, `go test ./...` green across unit tests, RFC 6962 / PAE / JCS /
run-binding known answers, emit-refusal seam tests, and the conformance
replay of the sibling vector suite: 61 accept vectors, 212 reject vectors,
2 indeterminate vectors, both key policies (pinned derived test key and
empty), all 275 strict
passes.

The attestor module compiles against the real go-witness module (workspace
mode, with a local go-witness checkout whose own dependency graph comes
from the module proxy). `go vet` is clean and `go test` is green:
emit-seam refusal on synthetic and vector bodies, a byte-for-byte
`MarshalJSON` round-trip, and a schema round-trip through the invopop
type.

End-to-end, library-mode runs of `aee-witness-demo` cover both
builder-generated and suite-vector evidence. Feeding it the accept vector
`vcc938c6038536dcb.json` as `aee-evidence.json` exits 0 with
a signed DSSE envelope whose payload statement carries the AEE
`predicateType`, the validated predicate bytes, and exactly one subject
(`example-agent-bundle`). Feeding it the reject vector
`v7ecdfe261d1dcd84.json` exits 1 with nothing signed, and
the operative error names the failing gate and code through the refusal
backstop (see the upstream observations below). A builder-generated
method-inflation evidence file also exits 1, with `refusing to sign:
statement fails GATE 1 (coverage validity): method-cap-exceeded`. On the
consumer side, `cmd/aee-verify` run against the suite returns
`{"verdict":"valid","result":"pass","tiers":["attested"]}` and exit 0 for
`ok-002` under the derived-key policy, and `batch-root-mismatch` with exit
1 for `bad-403` (its fault is a pad-last-node root).

To reproduce the attestor build here:

```
cp go.work.example go.work            # or: go work init . ./witnessattestor
# when a local go-witness checkout should satisfy the dep instead of the proxy:
#   go work use <path-to-go-witness-checkout>
cd witnessattestor && go build ./... && go test ./...
```

The core alone needs none of that: `go test ./...` at the tree root.

`go.work` and `go.work.sum` are committed so the attestor module builds
and tests out of the box (the sum file pins the go-witness dependency
graph). When the go-witness dependency is released and the attestor gains
a versioned `require` on the core, the workspace files can be dropped and
`witnessattestor/go.sum` generated in their place.

## Generator manifest isolation

The invalid-vector generators deep-copy the corpus manifest at statement
build time. An earlier version embedded the module-level manifest constant
by reference, so a builder that appended to one class list mutated the
shared constant and every later-built vector inherited an undeclared
second fault. The corpus digest was recomputed over the already-mutated
manifest, so the generators' own second-fault self-check (roots, digests,
bindings, signatures) could not see it, because manifest content faults
sit outside its four rederive surfaces. The differential replay against
the independent verifier caught the disagreement; the deep-copy at embed
time removes the aliasing class. The runner keeps an empty
`knownDefectiveVectors` quarantine set in `aee/vectors_test.go` for future
differential findings.

## Deliberate implementation pins (documented, spec-question-adjacent)

- Duplicate-record identity: duplicate leaf hashes are rejected, the safe
  superset of byte-identical-entry rejection (a record's canonical
  identity is its leaf hash). Admits no false accepts under either
  reading of the open spec question.
- Missing `basis`: a row with no `basis` member cannot be classified
  substrate. It is treated as a fail-closed non-substrate row (valid
  statement, recompute `fail`) pending the formal spec answer. The closed
  substrate-row gate keys strictly on `basis: substrate`.
- Covering set: covering means the referenced records of the class(es)
  the row's class-match rule requires; extras are payload-checked but
  neither cap nor tier-gate. Records that cover nothing do not
  participate in the method cap.
- `record-undecodable` is a registry-extension code for a record whose
  `payload` is not valid base64; `v4ff6cb70764bf703`
  exercises it.
- `record-signatures-empty` is a registry-extension code for a record
  carrying zero `signatures` entries, which the spec forbids. An absent
  member, an empty array and a member of the wrong JSON type are the same
  fault, since an entry count over a value that is not an array is
  undefined and undefined fails closed; the wrong-type spelling reports
  this code rather than the parse catch-all, which names neither the
  record nor the member. Counting entries needs no key material, so the
  check sits with the other coverage-validity checks and is the one
  signature-shaped question the byte-pure layer can answer; it verifies
  nothing, and a record carrying fabricated signature bytes passes it and
  is caught only at the tier. The count is asked once over the whole
  record set before any payload is decoded, which follows the spec's
  verify-then-read discipline: a record with no signature at all is
  settled ahead of the bytes it carries. `vca61adf35d265632`
  exercises the empty array, `ve0e5dddf8f3b812a` the
  wrong type, and `bad-748-signatures-empty-precedes-undecodable-record`
  pins the ordering against a statement that also carries an undecodable
  payload.
- JCS floats: vector payloads are integer-only per the suite's
  serialization pin. The ES6 double path in `aee/jcs.go` is exact for the
  common range and conservative (reject, never accept) at the extreme
  exponent boundaries.

## Upstream observations (for the go-witness PR conversation)

`runAttestor` swallows attestor failures into the sign path, found live in
v0.8.0's `attestation/context.go`. After recording a failed attestor's
error it falls through on a missing `return`, and appends a second
`CompletedAttestor` entry without the error; `run.go` then walks the
completed list and still calls `createAndSignEnvelope` for the error-free
duplicate of a refusing Exporter. Feeding the demo a reject-vector
evidence file, end to end, produced `failed to sign envelope: ...
MarshalJSON ...` rather than the seam's own error. The attestor guards against
this in two places. `MarshalJSON` refuses when no predicate was validated, and
that refusal is what actually stops the signature.
`Attest` also stores its refusal in `refusalErr`, which the backstop
names, so the operative failure reads as `attestor refused the evidence
and will not serialize a predicate: refusing to sign: statement fails
GATE 0 (well-formedness): vocabulary-digest-mismatch`. The one-line
upstream fix, adding `return` after the error append, belongs in the
staged go-witness PR.

Separately: an `Exporter` that does not also implement `Subjecter` is
silently skipped by the run loop with no error; the attestor implements
both, and the compile-time asserts pin it. The emitted outer statement's
`_type` is the witness library's statement version (`v0.1` at the tested
commit) -- the predicate and `predicateType` are unaffected, but it is
worth flagging upstream since it is not something this module can change.
And the witness `verify` CLI is coupled to its policy attestor, which is
why the standalone `cmd/aee-verify` (core module) exists as the
consume-side MVP; a `VerifyRunType` attestor is named future work.
