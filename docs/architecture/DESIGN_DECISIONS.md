# Design decisions

Choices a reader might otherwise flag as duplication, complexity, or dead code.
Each one is deliberate, and this file records why.

## Two independent verifier rails (do NOT de-duplicate across languages)

The suite ships two full reference verifiers: the stdlib-only Go verifier
(`aee/`) and the Python reference rail (`packaging/run_vectors.py`). They
re-implement the same primitives -- RFC 8785 JCS canonicalization, DSSE PAE,
RFC 6962 Merkle, ed25519, and the gate logic -- independently, in different
languages.

This cross-language duplication is deliberate. When two independent
implementations agree byte for byte, that agreement is what lets the corpus act
as a conformance authority: a bug or shortcut in one rail gets caught by the
other, and collapsing them onto a shared core would throw that away. Duplication
_within_ a language is debt worth removing; the cross-rail kind should stay.

## The generators' own self-verifier (a producer-side second opinion)

`vectors/accept/gen_valid_vectors.py` carries its own `verify()` -- a third
independent implementation of the gate logic -- run at build time as producer-QA
over every vector it emits. It is distinct from the two consumer rails: it
checks the generator's output before the vector is committed. It is deliberately
independent and is not shared with the rails.

## Hand-rolled ed25519 in the Python rail (test keys only)

`packaging/run_vectors.py` contains a pure-Python RFC 8032 ed25519
implementation rather than importing `cryptography`. This is deliberate: the
Python rail's zero-dependency portability is what lets a relying party run it
out of process with nothing but a stdlib Python, which is part of the
conformance-authority story. The keys are TEST keys only (never production), the
implementation is validated against `cryptography` and covered by a
known-answer test, and non-constant-time execution is an accepted non-goal.

## Generator primitives are copied, not shared (a deliberate non-abstraction)

The two generators each define the trivial primitives `jcs`, the sha256 hex
helper, and `pae` (about seven lines total). These are NOT factored into a
shared module. The generators are self-contained standalone scripts run directly
(`python3 vectors/<dir>/gen_*.py`); introducing a shared module would add
import-path machinery to both for a handful of trivial lines, trading real
coupling for negligible de-duplication, so the three similar lines are
duplicated rather than abstracted. (The generators' Merkle helpers
additionally diverge on purpose: the reject generator carries deliberately-wrong
attack variants -- `merkle_root_no_domain`, `merkle_root_dup_pad` -- that must
not be unified with the correct root.)

## Inherent complexity

A few functions have high cyclomatic complexity because the specification they
implement is itself branch-heavy, not because of tangled structure. The table
below explains why each one is complex.

The table covers every **non-test** Go function in `aee/`, `aeetest/`, `cmd/`,
and `witnessattestor/` and `corpora/` measured by gocyclo at **18 or above**; below that a
function is ordinary and needs no defence. Functions in `_test.go` files are out
of scope because their branch count tracks the number of cases they enumerate,
not the shipped verifier's structure. Every row today happens to live in `aee/`,
which is where the specification's branching lands.

`scripts/complexity-table-gate.py --rail go` enforces the table in CI. It fails
the build on a number that no longer matches, on an in-scope function at or above
the threshold with no row, and on a row whose function has been deleted or
refactored back below the threshold. Run it with `--sync` to rewrite the `Cyclo`
column from a fresh measurement after a legitimate change; adding or dropping a
row stays a hand edit, because the rationale is the part worth having and the
gate will not invent one.

| Function | Cyclo | Why it is inherent |
|---|---|---|
| `aee/validity.go` `checkSubstrateRow` | 33 | Per-row coverage in the order the requirements are stated: reference shape, then payload validity, then class match, then the method cap, each stage short-circuiting so a later one never reports on a row an earlier one already refused. The kind-specific constraints moved out to `armingConstraintsMet` and `sealedConstraintsMet`, and the closed-vocabulary guard to `rowFailsClosed`; what remains is the sequencing itself, which is the part that cannot be split without making the order a caller's business. |
| `aee/statement.go` `Gate0` | 36 | Statement well-formedness enumerates every reserved-member and vocabulary rule the spec lists; the branch count is the rule count. |
| `cmd/mutgen/mutate.go` `replaceExpr` | 35 | One arm per expression-bearing parent AST node, so the branch count is the node count. A reflect-keyed table would be shorter and would hide which parents are covered; a parent silently absent from it is a mutation that reports success and changes nothing, which scores as a forcing measurement that was never taken. |
| `cmd/mutgen/mutate.go` `collect` | 23 | Type dispatch over the AST node kinds that carry a weakening mutation, each with its own small enumeration rule. The branch count is the operator count, which is the published list in the command's own doc comment. |
| `aee/statement.go` `gate0CoverageIntegrity` | 19 | The coverage-partition invariant across three disjoint sets against the manifest. |
| `aee/jcs.go` `decodeValue` | 18 | Recursive JSON value dispatch with the I-JSON profile checks. |
| `corpora/pyjson.go` `encodePythonOpts` | 18 | Type dispatch over every JSON value CPython's `json.dumps` writes, one arm each, all of them trivial. The branch count is the JSON value-kind count plus the two refusals that keep a float from being spelled by guess. Two corpora name a member by the digest of exactly these bytes, so an arm quietly absent from a shorter table-driven form would move a digest rather than fail. |
| `aee/types.go` `parsePredicate` | 19 | One guarded decode per optional predicate member, plus the normalization that makes the three empty predicate states one value. Each member must record presence separately from value, because the gates distinguish an absent member from one that is present but malformed, so the branch count is the predicate's member count; the extra branch turns the nil map `null` decodes to into an empty one, so no later reader can key on the difference the framework says does not exist. |

The Python generators' functions carrying `# noqa: C901` are explained in
[`docs/complexity-rationales.toml`](../complexity-rationales.toml), and
`--rail python` gates that file against a fresh ruff measurement on exactly the
terms above.

The sentence that half replaces was wrong in a way worth recording. It said the
ruff `C901` threshold was already that rail's equivalent of this gate, which is
the reason no gate was written. It is not: `C901` reports a function above the
threshold, and a recorded function is by definition one carrying a
`# noqa: C901`, which silences the report. The linter was therefore silent about
precisely the numbers that were written down, and both of them drifted under it,
one by seven. The gate reads them with `--ignore-noqa` for that reason. A
threshold a linter enforces and a number a document records are different claims,
and only the second one was ever unchecked.

## The core is stdlib-only and go-witness-free

`aee/` imports nothing outside the Go standard library; `aee/imports_test.go`
enforces this at test time. The go-witness dependency lives only in the separate
`witnessattestor/` module, so a relying party can vendor the core verifier with
zero third-party supply-chain surface.
