# Incident-evidence-cell vectors

Cases for `incident-evidence-cell/v1`: one record is one coded cell of an incident
decision table, the table that crosses evidence states (rows) with responses (columns).
The record is an in-toto Statement v1 whose subjects are the source documents the cell
was coded from, by SHA-256, and whose predicate type is
`https://probityai.github.io/agent-evidence-vectors/predicate/v1/incident-evidence-cell`.

The producer signs the Statement in a DSSE envelope with its own key. Only the producer's
own cells carry its signature. A signature shows who coded a cell, never that the cell is
true, and every record says so in its own bytes.

[![Checked with Probity](https://img.shields.io/badge/checked-with_Probity-4c6278?style=flat-square&logo=data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAMAAABEpIrGAAAAkFBMVEX8%2B%2Bzr5NPgyrfKyLnSq5Wzo4tWltqRkZI2kPU1kvk1j%2FMwkPgzjfI2jO80jO40jO3MdWOZc1SLblN1aFxxXFJzVDY2i%2B40i%2B00i%2Bw0i%2Bs0ius1iOZAapwugNYtdbUqaq0qV4tkRzJXOB47Oz43JRkjNEYiHBwlFxIfFxMcEg0XEQ0WEAwXDAUWCAEOCQcJAgCa503RAAAB3klEQVR42rWT2ZacIBCGceHYoN240SK2Crig4vL%2BbxfszJyZTmaSm6S4rI9a%2FwK3vxj41wDj5E9AwS%2Foxjn7DmARqgVHCBHyJcBxJeZtEG2Nv4hAGEPXYVumddvWAbFfgJJECDfDukxa63ldmw%2FiCTCEK%2BteFzNbQI%2BbQPwzwKJGjNO2LMacxNqK1wgcNfO2mqfbHMs8NEkeXT8AjurRTKfbMlqOa5vFyc8cZclu4PSvWptlPlOMeb4PsQu78MoYQWFIwKUet0nPZl%2FMki1H3x%2FKd1PVhhdkS2tDgM7m9bR3XX8EXtYde59SSVVXNx2NMwuIbbGl74HUu%2BcFXrArSpXqlVSpGz8sUG%2FjoCej1RHA6ZAgl1SmUvVUQjduEGDIdt0MxuwjCHYNAZSwT1IbhaZ%2BFt7BrUAXbguxnx3gZ9AJVJLal0hKaYv4OShGbu249Z4F4jhQ1PcpTUYLDBF5WxZB9dBB14O%2Bm6eu48QQpjBXIizf113iS9sF0LYxZMD1PODbVvtznu96sGOrWyFEiwQEwHNcC8gaF58UxfG1qiqMqzx2AACJ0i0qXyRXEIwjwnD1SBOYdKJ%2B7vxF1eRUaxGF9ePRVgiX3xxOccdhiK5v6v%2Fysgp2Z%2BR%2F3ebv9gP5RU8tSdZhDwAAAABJRU5ErkJggg%3D%3D)](https://github.com/probityai/probity)

For anyone who codes incident playbooks, decision tables or regulatory guidance into cells
and wants each cell to carry who coded it, against which closed codes, and what it does
not claim.

```sh
pip install agent-evidence-vectors
python -m agent_evidence_vectors.evidencecell your-cell.json --json
agent-evidence-vectors --corpus vectors-incident-evidence-cell
python3 corpora/vectors-incident-evidence-cell/check_vectors.py --verifier './verifier'
```

The second line judges your own cells, one JSON line each with `decision` and `reason`;
it exits 1 when any cell is denied and 2 when one cannot be read. The third replays this
corpus through the packaged reader, the fourth through your verifier. A verifier takes
`record.json --json`, prints `{"decision": ..., "reason": ...}` and exits 0 for `allow`,
1 for `deny`.

## The record

```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [{"name": "source-document-1.md", "digest": {"sha256": "<64 hex>"}}],
  "predicateType": "https://probityai.github.io/agent-evidence-vectors/predicate/v1/incident-evidence-cell",
  "predicate": {
    "cell": {"table": "decision-table-1", "row": "ES3 row", "column": "investigation"},
    "state": "https://w3id.org/agent-evidence/vocab/v1/evidence_state#ES3",
    "response": "monitoring_increase",
    "supportLabel": "supported",
    "value": "raise monitoring on the affected hosts",
    "producer": {"id": "https://coder.example/coder-1"},
    "issuedAt": "2026-11-02T09:00:00Z",
    "registryDigest": {"sha256": "161bd780e265a99f27365c81bee12f5006ebb4e785a9563608ae98c52878a523"},
    "doesNotAssert": ["The signature shows who coded this cell, not that the cell is true."]
  }
}
```

- `state` is an [`evidence_state`](https://w3id.org/agent-evidence/vocab/v1/evidence_state)
  code in the form its term page emits, `...evidence_state#ES0` to `#ES8`.
- `response` is one value of the vocabulary term `response_function`.
- `supportLabel` is `supported`, `unsupported` or `unknown`.
- A cell carries exactly one of `value`, what the cell records, and
  `notAddressed: {"reason": ...}`, which marks the cell EMPTY. An empty cell is
  labelled `unknown`: nothing supports or refutes what the table leaves unsaid.
- `registryDigest` names the vocabulary registry snapshot the codes were read against.
  The corpus uses the committed snapshot
  `pages/vocab/v1/registry/sha256-161bd780e265a99f27365c81bee12f5006ebb4e785a9563608ae98c52878a523.yaml`;
  the reader checks the digest's form only.
- `doesNotAssert` must contain the exact sentence
  "The signature shows who coded this cell, not that the cell is true."

## From a decision table's columns to the closed values

| Column in the table | `response` |
| --- | --- |
| investigation | `monitoring_increase` |
| notification | `notification` |
| restriction | `restriction` |
| targeted isolation | `isolation` |
| wider pause | `pause` |
| remediation | `remediation` |
| restoration | `restoration` |

## What the cases force

The reader applies five checks in order and names the first that fails:
`statement_malformed` (the Statement type, the subject list, the predicate type, an
object predicate), `predicate_malformed` (the member set, the types, exactly one of
`value` and `notAddressed`, an https producer, a UTC time ending in `Z`, the digest form),
`closed_vocabulary_violation` (state, response or support label outside its closed set,
including a state written `/ES3` instead of `#ES3` and the column label `investigation`
written where `monitoring_increase` belongs), `empty_cell_labelled` (an empty cell labelled
anything but `unknown`) and `truth_disclaimer_missing` (the sentence absent or
paraphrased). Each denied case fails exactly its named check. The controls use every
response value, every support label, an empty cell, and the states `ES0`, `ES6` and
`ES8`. Counts are in `MANIFEST.json`.

## Synthetic, and labelled so

Every member is synthetic. The table, its rows and columns, the source documents and the
producer are fixed labels, and no member records a real organisation or incident. The
manifest says so in `synthetic`.

## What it does not test

Whether a cell is true, whether the source documents say what the cell records, or which
response a state calls for. Signature verification belongs to the DSSE envelope around the
Statement, not to this reader. Regenerate with
`python3 corpora/vectors-incident-evidence-cell/gen_vectors.py`.
