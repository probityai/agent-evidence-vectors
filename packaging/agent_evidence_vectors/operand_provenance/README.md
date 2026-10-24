# Declared-constant operand provenance

Executable cases for one provenance rule: a declared constant grounds an operand only
if the computation that ran actually read it, at the declared value. A declaration on
its own grounds nothing.

```sh
pip install agent-evidence-vectors
agent-evidence-vectors-operand-provenance --output out/
agent-evidence-vectors-operand-provenance --output out/ --verifier "my-verifier"
```

The first command judges every case with the package's reference reader. The second
hands each case to the verifier under test as `<verifier> <case-dir>/case.json --json`.
The verifier prints one JSON object with `decision` and `reason`. It exits 0 for
`supported`, 1 for `contradicted` or `not_established`, and 2 when it reaches no verdict.
The run exits 0 only when every case was answered and every answer matched.
`MANIFEST.json` lists every case with its expected answer and the SHA-256 of its file.

## Where the rule comes from

The failure is erratum E3 in [zorrzai/ap1-run](https://github.com/zorrzai/ap1-run),
the MIT-licensed reference instrument for the AP-1 admissibility protocol, recorded in
[FINDINGS_ERRATA.md at `650084d`](https://github.com/zorrzai/ap1-run/blob/650084da6927b3b97e81d3b160b0c6da646ea25a/FINDINGS_ERRATA.md#e3-q07-declared-an-unused-constant-d72a-figures-for-both-runs-are-withdrawn).
A derivation declared a constant its computation never used, and the provenance check
accepted operands carrying that value as grounded on the strength of the declaration.
Its author found it with a seal re-verification after many review passes had missed
it, withdrew the affected figures, and proposed this rule as check 3 of the operand
provenance sub-structure in
[finos/ai-governance-framework#359](https://github.com/finos/ai-governance-framework/issues/359#issuecomment-5859106168).
The case shapes follow that instrument's quarterly net-return item.

## What each case holds

`case.json` lists one or more derivations. Each has `declared_constants` and
`executed_reads`, both lists of `{id, value}` with decimal strings. `executed_reads` is
what the computation read when it ran, recorded by the computation layer; `null` means
nobody recorded it. The `operand` carries its `value` and its `grounding`: either
`{"kind": "constant", "derivation": ..., "constant": ...}` or `{"kind": "originated"}`.

## The checks

Each refused case changes one thing about a supported twin.

| Control | Supported | Refused |
| --- | --- | --- |
| Consumed | declared and read | declared, never read (`constant_declared_not_consumed`) |
| Declared | operand classed originated | constant claimed but not declared (`constant_not_declared`) |
| Precision | read at the declared value, or with a trailing zero | read rounded or extended away from the declared digits (`constant_value_differs_at_declared_precision`) |
| Operand | | operand value differs from the constant (`operand_value_differs`) |
| Observed | | reads not recorded (`not_established`, `consumption_unobservable`) |
| Route | a second route declared as its own derivation, which read the constant | the claim names a route that declared but did not read it |
| Form | | `executed_reads` absent (`no_verdict`) |

Values compare as exact decimals: `0.00650` equals a declared `0.0065`; `0.007` and
`0.00651` do not. The route pair answers the case for declaring domain constants so
that a valid alternative route is not flagged: declare that route as a derivation with
its own reads, and the operand names it.

The checks and their order are in [reader.py](reader.py).

## What a supported case does not establish

- that the computation layer recorded its reads truthfully;
- that the declared computation is the right one for the question;
- that operands grounded by source values, intermediates or earlier results resolve
  (the other checks of the sub-structure);
- that the figure is correct.
