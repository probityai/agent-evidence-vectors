# NIST AI 300-1 templates and profiles

A JSON form of the documentation templates and default profiles in [NIST AI 300-1 ipd](https://doi.org/10.6028/NIST.AI.300-1.ipd), *Guidance and Templates for Public-Facing AI Documentation* (initial public draft): Clause 5's dataset template (Table 1) and model template (Table 2), and Annex A's default dataset profile (Table A.2.1) and default model profile (Table A.3.1). Each table gets two JSON Schemas, one for what the draft requires and one for what it recommends, and a test set with a member for every rule and every branch of every condition. Every file is generated from the PDF and bound to it by digest.

## Run

From the repository root:

```bash
uv sync --locked --extra dev
uv run python interop/nist-ai-300-1/check_vectors.py
uv run python -m unittest discover -s interop/nist-ai-300-1 -p test_check_vectors.py
uv run python interop/nist-ai-300-1/gen_vectors.py   # rewrites the same bytes
```

The checker prints:

```text
ok: 4 tables on 26 pages and 7 reviewer notes make up all 33 ruled boxes in the 54-page PDF, 157 rows by both extractions; 235 members over 139 rules; source and 9 bindings re-derived; 143 deletions and 50 dropped conditions each flipped the members that name them
```

CI runs the same steps, and checks that regeneration leaves the tree unchanged, in [nist-ai-300-1.yml](../../.github/workflows/nist-ai-300-1.yml). `check_vectors.py --counts` prints every figure on this page.

## What is in it

| File | What it is |
|---|---|
| [source/NIST.AI.300-1.ipd.pdf](source/NIST.AI.300-1.ipd.pdf) | The draft, byte for byte, SHA-256 `d38f4ce0...9777e`. |
| [templates.json](templates.json) | Every row of the four tables and the text of the five clauses that govern them, as the PDF prints them. |
| [schemas/](schemas/) | `<table>.conformance.schema.json` (required fields) and `<table>.recommended.schema.json` (recommended fields), JSON Schema 2020-12. |
| [members/](members/) and [INDEX.md](INDEX.md) | 235 test documents, each with its expected verdict under both schemas. |
| [MANIFEST.json](MANIFEST.json) | The digests, the completeness census, every rule, every member, and the readings below. |
| [readings.json](readings.json) | The only hand-written input: how each conditional cell reads as a rule. |

## Completeness

Completeness is counted on the PDF's structures, not its characters. The census in `extract.py` reads every page and finds 33 ruled boxes and 26 caption lines. Of the boxes, 26 are pages of the four tables, on exactly the pages each caption names, and the other 7 are the draft's notes to reviewers, which carry no fields. Each table's row IDs are read twice, once from PyMuPDF's cell grid and once from the word positions `extract.py` uses, and both give the same 157 IDs in the same order: 7, 8, 71 and 71. A caption naming any other table, a ruled box nobody accounts for, a table page left out or a row merged away fails both the generator and the checker; `test_check_vectors.py` shows each refusal.

| Table | Clause | Fields | Rules | Conditions | Members |
|---|---|---|---|---|---|
| Table 1: Dataset documentation template | 5.2 | 7 | 5 | 0 | 7 |
| Table 2: Model documentation template | 5.3 | 8 | 4 | 0 | 6 |
| Table A.2.1: Default AI dataset profile | A.2 | 71 | 69 | 19 | 122 |
| Table A.3.1: Default AI model profile | A.3 | 71 | 61 | 16 | 100 |

## How a member proves a rule

Each member plays one or more roles, listed in INDEX.md. A member that `violates` a rule breaks that rule alone, and deleting the rule from its schema flips the member's verdict. A member that is `inapplicable` to a conditional rule leaves the field out while the condition does not hold, and dropping the condition flips it. A member that `satisfies` a rule makes the condition hold and supplies the field. The checker runs all 143 deletions and 50 condition drops on every run and fails if any member does not flip.

## Where the draft leaves a reading open

The draft does not settle everything, and the corpus says so rather than guessing. MANIFEST.json lists 12 ambiguities with the quoted cell and the reading the schemas take, among them a Table A.3.1 row whose Description and Designation cells are transposed (A1) and parent pointers that name fields the table does not print (A2, A3). It lists 5 observations, such as the dataset profile citing Clause 5.3 where the dataset template is Clause 5.2 (O2). And it lists 13 requirements no schema over a document's structure can check, such as "Shall provide enough information to determine whether a given dataset is the one described". One member's recommended verdict depends on an open reading; INDEX.md leaves it blank and MANIFEST.json says why.

## Source

The PDF is a U.S. Government work published by NIST at <https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.300-1.ipd.pdf>, captured on 2026-10-13. The text it yields depends on the extractor, so PyMuPDF is pinned exactly in `pyproject.toml`, and the release that produced the digests is recorded in MANIFEST.json.
