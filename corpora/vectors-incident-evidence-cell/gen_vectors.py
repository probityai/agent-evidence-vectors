"""Build the incident-evidence-cell cases byte-identically.

Every case is one coded cell of a decision table, as an in-toto Statement v1.
The allowed cases are controls: together they use every response value, every
support label, an empty cell and the states ES0, ES6 and ES8, so a verifier that
denies everything, or refuses a valid closed code, fails the corpus. Each denied
case changes a control so the check it names is the first that fails and every
earlier check passes. Every member is synthetic: the table, its rows and columns,
the source documents and the producer are fixed labels, and no member records a
real organisation or incident.
"""

from __future__ import annotations

import copy
import hashlib
import json
import shutil
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parents[1] / "packaging"))

from agent_evidence_vectors import evidencecell as reader  # noqa: E402

SUITE = reader.SUITE
TABLE = "decision-table-1"
PRODUCER = "https://coder.example/coder-1"
SECOND_SENTENCE = ("The coded state is read from the source documents named as subjects, "
                   "not observed directly.")
#: A decision table's seven response columns and the closed response_function
#: value each maps to.
COLUMNS = {
    "investigation": "monitoring_increase",
    "notification": "notification",
    "restriction": "restriction",
    "targeted isolation": "isolation",
    "wider pause": "pause",
    "remediation": "remediation",
    "restoration": "restoration",
}


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()


def _source(n: int) -> dict[str, Any]:
    name = f"source-document-{n}.md"
    return {"digest": {"sha256": _sha(f"synthetic source document {n}\n".encode())},
            "name": name}


def build(code: int, column: str, label: str, value: str | None = None, /, *,
          sources: int = 1, **members: Any) -> dict[str, Any]:
    """One coded cell: row ``ES<state>``, a column of the table, its label and content."""
    predicate: dict[str, Any] = {
        "cell": {"column": column, "row": f"ES{code} row", "table": TABLE},
        "doesNotAssert": [reader.DISCLAIMER, SECOND_SENTENCE],
        "issuedAt": "2026-11-02T09:00:00Z",
        "producer": {"id": PRODUCER},
        "registryDigest": {"sha256": reader.REGISTRY_DIGEST},
        "response": COLUMNS[column],
        "state": f"{reader.STATE_TERM}#ES{code}",
        "supportLabel": label,
    }
    if value is None:
        predicate["notAddressed"] = {"reason": "the table leaves this cell empty"}
    else:
        predicate["value"] = value
    predicate.update(members)
    return {
        "_type": reader.STATEMENT_TYPE,
        "predicate": {key: item for key, item in predicate.items() if item is not None},
        "predicateType": reader.PREDICATE_TYPE,
        "subject": [_source(n) for n in range(1, sources + 1)],
    }


def restate(statement: dict[str, Any], **top: Any) -> dict[str, Any]:
    """The statement with top-level members replaced, or removed where given None."""
    changed = {**copy.deepcopy(statement), **top}
    return {key: item for key, item in changed.items() if item is not None}


Case = tuple[str, dict[str, Any], str, str, str]


def _controls() -> list[Case]:
    ok, allow = reader.ALLOWED_REASON, "allow"
    return [
        ("allow-investigation-supported",
         build(3, "investigation", "supported", "raise monitoring on the affected hosts"),
         allow, ok, "control: an investigation cell supported by its source"),
        ("allow-notification-unsupported",
         build(2, "notification", "unsupported", "notify the regulator within one hour"),
         allow, ok, "control: a notification cell its source does not support"),
        ("allow-restriction-supported",
         build(4, "restriction", "supported", "restrict outbound calls from the agent"),
         allow, ok, "control: a restriction cell supported by its source"),
        ("allow-isolation-supported",
         build(5, "targeted isolation", "supported", "isolate the agents on the pathway"),
         allow, ok, "control: a targeted-isolation cell maps to isolation"),
        ("allow-pause-unknown-value",
         build(7, "wider pause", "unknown", "pause every agent in the fleet"),
         allow, ok, "control: a recorded value whose support is unknown"),
        ("allow-remediation-empty-es6",
         build(6, "remediation", "unknown"),
         allow, ok, "control: an empty cell at ES6, labelled unknown"),
        ("allow-restoration-es8",
         build(8, "restoration", "supported", "restart under the recorded containment"),
         allow, ok, "control: a restoration cell at ES8"),
        ("allow-empty-investigation-es0",
         build(0, "investigation", "unknown"),
         allow, ok, "control: an empty cell at ES0, labelled unknown"),
        ("allow-two-source-documents",
         build(1, "notification", "supported", "record the measured silence", sources=2),
         allow, ok, "control: a cell coded from two source documents"),
    ]


def _statement_cases(base: dict[str, Any]) -> list[Case]:
    other = reader.PREDICATE_TYPE.replace("/predicate/v1/", "/predicate/v2/")
    upper = restate(base, subject=[{**_source(1), "digest": {
        "sha256": _sha(b"synthetic source document 1\n").upper()}}])
    reason = "statement_malformed"
    return [
        ("reject-statement-type-old", restate(base, _type="https://in-toto.io/Statement/v0.1"),
         "deny", reason, "a Statement type other than in-toto v1"),
        ("reject-subject-empty", restate(base, subject=[]),
         "deny", reason, "a cell that names no source document"),
        ("reject-subject-digest-uppercase", upper,
         "deny", reason, "a source digest written in upper-case hex"),
        ("reject-predicate-type-other", restate(base, predicateType=other),
         "deny", reason, "a predicate type this host does not define"),
        ("reject-predicate-not-object", restate(base, predicate=[base["predicate"]]),
         "deny", reason, "a predicate that is a list, not an object"),
    ]


def _predicate_cases() -> list[Case]:
    reason, column = "predicate_malformed", "investigation"
    both = build(3, column, "supported", "raise monitoring",
                 notAddressed={"reason": "the table leaves this cell empty"})
    return [
        ("reject-value-and-not-addressed", both, "deny", reason,
         "a cell that records a value and also says it is empty"),
        ("reject-neither-value-nor-not-addressed",
         build(3, column, "supported", notAddressed=None), "deny", reason,
         "a cell with neither a value nor an empty marker"),
        ("reject-value-empty-string", build(3, column, "supported", ""), "deny", reason,
         "an empty string offered as the recorded value"),
        ("reject-producer-http",
         build(3, column, "supported", "raise monitoring",
               producer={"id": "http://coder.example/coder-1"}), "deny", reason,
         "a producer identified by a plain http URL"),
        ("reject-issued-at-offset",
         build(3, column, "supported", "raise monitoring", issuedAt="2026-11-02T09:00:00+00:00"),
         "deny", reason, "a time with a numeric offset instead of Z"),
        ("reject-registry-digest-short",
         build(3, column, "supported", "raise monitoring",
               registryDigest={"sha256": reader.REGISTRY_DIGEST[:40]}), "deny", reason,
         "a registry digest forty hex digits long"),
        ("reject-extra-member",
         build(3, column, "supported", "raise monitoring", confidence="high"), "deny", reason,
         "a predicate member the type does not define"),
        ("reject-does-not-assert-empty",
         build(3, column, "supported", "raise monitoring", doesNotAssert=[]), "deny", reason,
         "an empty list of what the record does not assert"),
    ]


def _vocabulary_cases() -> list[Case]:
    reason, column = "closed_vocabulary_violation", "investigation"
    return [
        ("reject-state-slash-form",
         build(3, column, "supported", "raise monitoring",
               state=f"{reader.STATE_TERM}/ES3"), "deny", reason,
         "the state written with /ES3, a URI the term page does not emit"),
        ("reject-state-es9",
         build(3, column, "supported", "raise monitoring", state=f"{reader.STATE_TERM}#ES9"),
         "deny", reason, "a state code the vocabulary does not define"),
        ("reject-response-investigation",
         build(3, column, "supported", "raise monitoring", response="investigation"),
         "deny", reason, "the table's column label written where the closed value belongs"),
        ("reject-support-label-partial",
         build(3, column, "partially_supported", "raise monitoring"), "deny", reason,
         "a support label outside supported, unsupported and unknown"),
    ]


def _denied() -> list[Case]:
    base = build(3, "investigation", "supported", "raise monitoring on the affected hosts")
    paraphrase = "The signature shows who coded the cell, not that it is true."
    return [
        *_statement_cases(base),
        *_predicate_cases(),
        *_vocabulary_cases(),
        ("reject-empty-cell-supported", build(6, "remediation", "supported"),
         "deny", "empty_cell_labelled", "an empty cell labelled supported"),
        ("reject-empty-cell-unsupported", build(0, "notification", "unsupported"),
         "deny", "empty_cell_labelled", "an empty cell labelled unsupported"),
        ("reject-disclaimer-paraphrased",
         build(3, "investigation", "supported", "raise monitoring",
               doesNotAssert=[paraphrase, SECOND_SENTENCE]),
         "deny", "truth_disclaimer_missing", "the disclaimer paraphrased, not stated"),
        ("reject-disclaimer-absent",
         build(3, "investigation", "supported", "raise monitoring",
               doesNotAssert=[SECOND_SENTENCE]),
         "deny", "truth_disclaimer_missing", "no disclaimer among what the record does not "
         "assert"),
    ]


def cases() -> list[Case]:
    """Every case: id, record, decision, reason, and what it shows."""
    return [*_controls(), *_denied()]


def corpus_digest(manifest: dict[str, Any], root: str) -> str:
    """Recompute the digest from the committed files, not their declared hashes."""
    base_dir = Path(root)
    entries = []
    for entry in manifest["vectors"]:
        directory = base_dir / entry["path"]
        declared = entry["files"]
        if {p.name for p in directory.iterdir() if p.is_file()} != set(declared):
            raise ValueError(f"{entry['id']}: file set changed")
        files = {name: _sha((directory / name).read_bytes()) for name in declared}
        if files != declared:
            raise ValueError(f"{entry['id']}: file digest mismatch")
        entries.append({**entry, "files": files})
    return _sha(_json(entries))


def generate(root: Path = ROOT) -> dict[str, Any]:
    """Write every case and the manifest, and return the manifest."""
    if (root / "cases").exists():
        shutil.rmtree(root / "cases")
    entries = []
    for name, body, decision, reason, edit in cases():
        directory = root / "cases" / name
        directory.mkdir(parents=True)
        data = _json(body)
        (directory / "record.json").write_bytes(data)
        expected = {"decision": decision, "reason": reason}
        observed = reader.verify(directory / "record.json")
        if observed != expected:
            raise SystemExit(f"{name}: the reader says {observed}, the case {expected}")
        entries.append({"edit": edit, "expected": expected,
                        "files": {"record.json": _sha(data)}, "id": name,
                        "path": f"cases/{name}", "retained": reader.retained(copy.deepcopy(body))})
    words = [entry["expected"]["decision"] for entry in entries]
    manifest = {
        "corpusDigest": _sha(_json(entries)),
        "counts": {word: words.count(word) for word in sorted(set(words))},
        "predicateType": reader.PREDICATE_TYPE,
        "registryDigest": reader.REGISTRY_DIGEST,
        "suite": SUITE,
        "synthetic": True,
        "verifierContract": "verifier record.json --json; exit 0 allow, 1 deny",
        "vectors": entries,
    }
    (root / "MANIFEST.json").write_bytes(_json(manifest))
    return manifest


if __name__ == "__main__":
    generate()
