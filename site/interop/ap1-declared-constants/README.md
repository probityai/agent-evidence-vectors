# Declared constants a derivation never uses

AP-1's grounding rule lets a declared constant ground an operand. Erratum E3 in
[zorrzai/ap1-run](https://github.com/zorrzai/ap1-run/blob/77514b4c3ad56a3b0ef48b460be014ed3dbb1370/FINDINGS_ERRATA.md)
records what that admits when the constant is declared and not used: Q07 declared
`4`, its computation never used it, and every operand equal to `4` resolved as
grounded. The erratum is MIT-licensed, and this case is built on it with credit
to its author.

ap1-run's own seal check covers the other direction, a constant used and not
declared. Its test `test_e3b_ast_check_allows_unused_constants` requires a
declared, unused constant to pass. `check.py` covers that direction: a declared
constant must appear in the computation of the derivation that declares it.

## Run it

```bash
python3 -I check.py path/to/ground_truth_example.py     # exit 0 pass, 1 fail, 2 unreadable
python3 -I -m unittest discover -s tests -v              # synthetic known answers
python3 -I replay.py                                     # the five pinned ap1-run states below
```

`check.py` reads the module as source and never imports or runs it. It uses the
standard library only.

## Pinned results

`replay.py` reads `example/ground_truth_example.py` at each commit and holds the
answer to `expected.json`. `results.json` is the retained output, with each
file's sha256.

| Commit | State | Result | Declared, never used |
| --- | --- | --- | --- |
| `203fef4` | module bound by the August run seals | fail | Q07: `4` |
| `83afb5e` | after the August runs, before the fix | fail | Q07: `2`, `4` |
| `85e8eeb` | the E3 fix | pass | none |
| `a322275` | module bound by the September run seals (tag `e7-quantise-fix`) | fail | Q07: `4` |
| `77514b4` | default branch on 13 October 2026 | fail | Q07: `4` |

The `a322275` file's sha256 is `033ce73d...`, the `ground_truth_hash` the
September seals bind. Commit `ff8c051` declared `4` on Q07 again, on the
`monthly_return` step, with a comment that dividing an annual figure by 4 is a
valid route. The step computes `balance * rate / 100 / 12`, so the declared
derivation does not use it.

## Limits

- The comparison is per derivation function, not per step. A constant declared
  on one step and used only in another passes.
- Any numeric literal in the function counts as a use, including one that is
  not arithmetic. The check can miss an unused constant; it cannot report a used
  one as unused.
- It reads `{"constant": "<value>"}` declarations and `D("...")`,
  `Decimal("...")` or bare-number uses. A module that spells either differently
  is not read.
- Whether a declared, unused constant should ground an operand is AP-1's rule to
  set. This case reports the condition; it does not score any run.
