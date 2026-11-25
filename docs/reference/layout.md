# Code layout

Start in the verification core for statement behavior, the packaging harness for external comparisons, or a corpus reader for a format-specific replay.

| Path | Job |
| --- | --- |
| [go.mod](../../go.mod) | Core Go module; stdlib-only, enforced by test |
| [aee/statement.go](../../aee/statement.go) | GATE 0: statement well-formedness |
| [aee/validity.go](../../aee/validity.go) | GATE 1: coverage validity |
| [aee/recompute.go](../../aee/recompute.go) | Pure result recomputation |
| [aee/tier.go](../../aee/tier.go) | GATE 2: declared, unattested or attested evidence |
| [aee/runbinding.go](../../aee/runbinding.go) | Versioned run binding; one accepted construction |
| [aee/merkle.go](../../aee/merkle.go) | RFC 6962 domain separation, recursive split and duplicate rejection |
| [aee/pae.go](../../aee/pae.go) | DSSE pre-authentication encoding and digest helpers |
| [aee/jcs.go](../../aee/jcs.go) | RFC 8785 canonicalization and RFC 7493 I-JSON checks |
| [aee/types.go](../../aee/types.go), [aee/codes.go](../../aee/codes.go) | Statement types and failure-code registry |
| [aee/](../../aee/) | Unit tests, known answers and corpus replay tests |
| [aeetest/](../../aeetest/) | Synthetic statements and derived test keys |
| [cmd/aee-verify/](../../cmd/aee-verify/) | Statement CLI and registered corpus readers |
| [corpora/](../../corpora/) | Format-specific readers selected by manifest suite |
| [signed-claims-corpora.md](signed-claims-corpora.md) | Layout of a corpus whose records are small signed JSON claims, with a Python and a Go reader that must agree |
| [packaging/run_vectors.py](../../packaging/run_vectors.py) | Python reference rail, external-verifier harness and reports |
| [cmd/mutgen/](../../cmd/mutgen/), [cmd/mutrun/](../../cmd/mutrun/) | Single-site weakening and in-process corpus replay |
| [witnessattestor/](../../witnessattestor/) | Separate go-witness module and library demo |
| [go.work.example](../../go.work.example) | Workspace wiring for the attestor; see [BUILD-NOTES.md](../../BUILD-NOTES.md) |
