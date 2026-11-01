# Mutation sweep

Relax each row in turn and replay the whole corpus against the validator with
that row switched off. A member FLIPS when its judgement changes: a reject
member that stops being rejected, or an accept member that starts being. The
claim the table makes is the one a rejection corpus owes and nobody on the list
had measured: relaxing a row flips every member that names it and no member
that does not. A row whose members did not all flip is a row the corpus does
not force; a row that flipped a member elsewhere is a member carrying a second
fault under the name of a first.

Emitted by `gen_vectors.py` on every regeneration, over every member of the
corpus and every row of its manifest. Rows that leak: 0.

| row | members naming it | flipped | flipped elsewhere | verdict |
|---|---|---|---|---|
| `W3C-R-001` | 1 | 1 | 0 | isolated |
| `W3C-R-002` | 1 | 1 | 0 | isolated |
| `W3C-R-003` | 1 | 1 | 0 | isolated |
| `W3C-R-004` | 1 | 1 | 0 | isolated |
| `W3C-R-005` | 1 | 1 | 0 | isolated |
| `W3C-R-006` | 1 | 1 | 0 | isolated |
| `W3C-R-007` | 1 | 1 | 0 | isolated |
| `W3C-R-008` | 1 | 1 | 0 | isolated |
| `W3C-R-009` | 1 | 1 | 0 | isolated |
| `W3C-R-010` | 1 | 1 | 0 | isolated |
| `W3C-R-011` | 1 | 1 | 0 | isolated |
| `W3C-R-012` | 1 | 1 | 0 | isolated |
| `W3C-R-025` | 1 | 1 | 0 | isolated |
| `W3C-R-026` | 1 | 1 | 0 | isolated |
| `W3C-R-019` | 1 | 1 | 0 | isolated |
| `W3C-R-024` | 1 | 1 | 0 | isolated |
| `W3C-R-016` | 1 | 1 | 0 | isolated |
| `W3C-R-021` | 1 | 1 | 0 | isolated |
| `W3C-R-027` | 1 | 1 | 0 | isolated |
| `W3C-R-028` | 1 | 1 | 0 | isolated |
| `W3C-R-020` | 21 | 21 | 0 | isolated |
| `W3C-R-015` | 6 | 6 | 0 | isolated |
| `W3C-R-017` | 1 | 1 | 0 | isolated |
| `W3C-R-023` | 4 | 4 | 0 | isolated |
| `W3C-R-018` | 1 | 1 | 0 | isolated |
| `W3C-R-013` | 4 | 4 | 0 | isolated |
| `W3C-R-014` | 1 | 1 | 0 | isolated |
| `W3C-R-029` | 2 | 2 | 0 | isolated |
| `W3C-R-033` | 2 | 2 | 0 | isolated |
| `W3C-R-022` | 2 | 2 | 0 | isolated |
| `W3C-R-030` | 0 | 0 | 0 | isolated |
| `W3C-R-031` | 0 | 0 | 0 | isolated |
| `W3C-R-032` | 0 | 0 | 0 | isolated |
| `ARM-R-001` | 1 | 1 | 0 | isolated |
| `ARM-R-002` | 1 | 1 | 0 | isolated |
| `ARM-R-003` | 1 | 1 | 0 | isolated |
| `ARM-R-004` | 1 | 1 | 0 | isolated |
| `ARM-R-005` | 1 | 1 | 0 | isolated |
| `ARM-R-006` | 1 | 1 | 0 | isolated |
| `ARM-R-007` | 1 | 1 | 0 | isolated |
| `ARM-R-008` | 1 | 1 | 0 | isolated |
| `ARM-R-009` | 1 | 1 | 0 | isolated |
| `ARM-R-010` | 1 | 1 | 0 | isolated |
| `ARM-R-011` | 1 | 1 | 0 | isolated |
| `ARM-R-012` | 1 | 1 | 0 | isolated |
| `ARM-R-013` | 1 | 1 | 0 | isolated |
| `ARM-R-014` | 2 | 2 | 0 | isolated |
| `ARM-R-015` | 1 | 1 | 0 | isolated |
| `ARM-R-016` | 1 | 1 | 0 | isolated |
| `ARM-R-017` | 1 | 1 | 0 | isolated |
| `ARM-R-018` | 1 | 1 | 0 | isolated |
| `ARM-R-019` | 1 | 1 | 0 | isolated |
| `ARM-R-020` | 1 | 1 | 0 | isolated |
| `ARM-R-021` | 1 | 1 | 0 | isolated |
| `ARM-R-022` | 1 | 1 | 0 | isolated |
| `LCD-R-001` | 1 | 1 | 0 | isolated |
| `LCD-R-002` | 1 | 1 | 0 | isolated |
| `LCD-R-003` | 1 | 1 | 0 | isolated |
| `LCD-R-004` | 1 | 1 | 0 | isolated |
| `LCD-R-005` | 1 | 1 | 0 | isolated |
| `LCD-R-006` | 1 | 1 | 0 | isolated |
| `LCD-R-007` | 1 | 1 | 0 | isolated |
| `LCD-R-008` | 1 | 1 | 0 | isolated |
| `LCD-R-009` | 1 | 1 | 0 | isolated |
| `LCD-R-010` | 1 | 1 | 0 | isolated |
| `LCD-R-011` | 1 | 1 | 0 | isolated |

## The digest encoding, one rule at a time

The members of the digest-encoding families (proposed: 2026Oct/0038 and 0040)
are rejected under rows the text already has, W3C-R-020 and W3C-R-015, so
relaxing a row above cannot say which rule of the encoding a member rests on.
This table switches off one rule of the encoding at a time
(`w3creport.WEAKENABLE`) and replays the corpus. Every reject member of a
family must flip under the family's rule, because its root is the one that
rule's absence writes; no reject member of another family may flip, and no
member outside these families may flip at all. An accept member flips under
every rule its value touches, which is why the accept column names families.

| rule | families resting on it | reject members | reject members flipped | accept members flipped | other rejects flipped | other members flipped | verdict |
|---|---|---|---|---|---|---|---|
| `utf16-member-order` | `w3c-f-jcs-member-order` | 1 | 1 | 1 (`w3c-f-jcs-member-order`) | 0 | 0 | isolated |
| `raw-u007f` | `w3c-f-jcs-u007f` | 1 | 1 | 1 (`w3c-f-jcs-u007f`) | 0 | 0 | isolated |
| `raw-non-ascii` | `w3c-f-jcs-non-ascii` | 4 | 4 | 5 (`w3c-f-jcs-member-order`, `w3c-f-jcs-non-ascii`) | 0 | 0 | isolated |
| `number-by-value` | `w3c-f-jcs-number-value` | 3 | 3 | 3 (`w3c-f-jcs-number-value`) | 0 | 0 | isolated |
| `integers-only` | `w3c-f-jcs-non-integer` | 3 | 3 | 0 (none) | 0 | 0 | isolated |
| `safe-range` | `w3c-f-jcs-1e21`, `w3c-f-jcs-safe-range` | 6 | 6 | 0 (none) | 0 | 0 | isolated |
| `closed-encoding-set` | `w3c-f-jcs-declaration` | 1 | 1 | 0 (none) | 0 | 0 | isolated |

Each reject member, the rule it rests on, the row it is rejected under and the
cause that rejection names:

| member | family | rule | row | cause |
|---|---|---|---|---|
| `v0a887e6b24bdd940` | `w3c-f-jcs-safe-range` | `safe-range` | W3C-R-020 | integer-outside-safe-range |
| `v16bbc5bfef80043e` | `w3c-f-jcs-safe-range` | `safe-range` | W3C-R-020 | integer-outside-safe-range |
| `v1afe0d60b2df5d39` | `w3c-f-jcs-non-integer` | `integers-only` | W3C-R-020 | non-integer-number |
| `v26a379aeeebabd1e` | `w3c-f-jcs-non-integer` | `integers-only` | W3C-R-020 | non-integer-number |
| `v2b4990ad53fbf28b` | `w3c-f-jcs-non-integer` | `integers-only` | W3C-R-020 | non-integer-number |
| `v3fd6a6a262a72f91` | `w3c-f-jcs-non-ascii` | `raw-non-ascii` | W3C-R-020 | digests-differ |
| `v40ab7c6deec16438` | `w3c-f-jcs-1e21` | `safe-range` | W3C-R-020 | integer-outside-safe-range |
| `v4193637206138b32` | `w3c-f-jcs-non-ascii` | `raw-non-ascii` | W3C-R-020 | digests-differ |
| `v5196f1761ea14b2b` | `w3c-f-jcs-non-ascii` | `raw-non-ascii` | W3C-R-020 | digests-differ |
| `v522b0a6b91e74c95` | `w3c-f-jcs-safe-range` | `safe-range` | W3C-R-020 | integer-outside-safe-range |
| `v60bd06deca6e832d` | `w3c-f-jcs-u007f` | `raw-u007f` | W3C-R-020 | digests-differ |
| `v64e02942221729d2` | `w3c-f-jcs-declaration` | `closed-encoding-set` | W3C-R-015 | unsupported-digest-encoding |
| `v8474a83c45f293fc` | `w3c-f-jcs-non-ascii` | `raw-non-ascii` | W3C-R-020 | digests-differ |
| `v920852737e02ae49` | `w3c-f-jcs-number-value` | `number-by-value` | W3C-R-020 | digests-differ |
| `v9d05fc7c9c249317` | `w3c-f-jcs-member-order` | `utf16-member-order` | W3C-R-020 | digests-differ |
| `v9ff65c5b03dd074c` | `w3c-f-jcs-number-value` | `number-by-value` | W3C-R-020 | digests-differ |
| `va8dfb25c6d62d458` | `w3c-f-jcs-safe-range` | `safe-range` | W3C-R-020 | integer-outside-safe-range |
| `vb37f841c9e91bf18` | `w3c-f-jcs-1e21` | `safe-range` | W3C-R-020 | integer-outside-safe-range |
| `vc3fa59108d1ead8a` | `w3c-f-jcs-number-value` | `number-by-value` | W3C-R-020 | digests-differ |
