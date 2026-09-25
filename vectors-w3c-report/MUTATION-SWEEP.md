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
| `W3C-R-013` | 2 | 2 | 0 | isolated |
| `W3C-R-014` | 1 | 1 | 0 | isolated |
| `W3C-R-015` | 5 | 5 | 0 | isolated |
| `W3C-R-016` | 43 | 43 | 0 | isolated |
| `W3C-R-017` | 1 | 1 | 0 | isolated |
| `W3C-R-018` | 1 | 1 | 0 | isolated |
| `W3C-R-019` | 1 | 1 | 0 | isolated |
| `W3C-R-020` | 3 | 3 | 0 | isolated |
| `W3C-R-021` | 1 | 1 | 0 | isolated |
| `W3C-R-022` | 2 | 2 | 0 | isolated |
| `W3C-R-023` | 2 | 2 | 0 | isolated |
| `W3C-R-024` | 1 | 1 | 0 | isolated |
| `W3C-R-025` | 1 | 1 | 0 | isolated |
| `W3C-R-026` | 1 | 1 | 0 | isolated |
| `W3C-R-027` | 1 | 1 | 0 | isolated |
| `W3C-R-028` | 1 | 1 | 0 | isolated |
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
| `ARM-R-014` | 1 | 1 | 0 | isolated |
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
