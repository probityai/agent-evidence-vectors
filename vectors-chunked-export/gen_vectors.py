"""Build the chunked-export cases byte-identically.

Every case is the export gate's view when one chunk of a flagged dataset is
presented: the chunks already exported, the reconstruction rule the issuer
committed to, and the class the seal declares. The decisions for Variant A
(boundary B2: a flagged dataset exported in chunks, each chunk reversible on its
own) are the ones Mayur Agnihotri posted on probityai/agent-evidence#24
(issuecomment-6247271570): a gate reading the maximum of the per-step labels
permits at every chunk, and a composition-aware gate permits below the
threshold and denies at the crossing chunk and after it. The committed-k cases
follow the pre-fixed completion criterion of probityai/agent-evidence-vectors#80.
The set cases follow his point on the same comment that reconstruction can
depend on which chunks have left rather than on how many.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent / "packaging"))

from agent_evidence_vectors import chunkedexport as reader  # noqa: E402

SUITE = reader.SUITE
SOURCE = {
    "thread": "https://github.com/probityai/agent-evidence/issues/24#issuecomment-6247271570",
    "author": "Mayur021",
    "variant": "Variant A, boundary B2",
}
DATASET = [f'{{"chunk":{i},"rows":"flagged-dataset rows {i * 100}-{i * 100 + 99}"}}\n'.encode()
           for i in range(5)]
DATASET_SHA = hashlib.sha256(b"".join(DATASET)).hexdigest()
COMMITTED = "2026-10-10T10:59:00Z"
COMMITTED_LATE = "2026-10-10T11:00:30Z"
COUNT = {"kind": "count", "k": 3, "committedAt": COMMITTED}
# Chunk 3 carries the key field: alone it reconstructs the dataset; without it
# chunks 0, 1 and 2 together are needed.
SETS = {"kind": "sets", "minimalSets": [[0, 1, 2], [3]], "committedAt": COMMITTED}


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()


def chunk(index: int, step_class: str = reader.REVERSIBLE) -> dict[str, Any]:
    return {"index": index, "leftAt": f"2026-10-10T11:0{index}:00Z",
            "payloadFile": f"chunk-{index}.bin", "payloadSha256": _sha(DATASET[index]),
            "stepClass": step_class}


def record(exported: list[int], seal: str, *, rule: dict[str, Any] | None = None,
           irreversible: frozenset[int] = frozenset(),
           contract: str | None = reader.CONTRACT_ID) -> dict[str, Any]:
    """One gate record; every argument is a departure from the permitted record."""
    body: dict[str, Any] = {
        "chunks": [chunk(i, reader.IRREVERSIBLE if i in irreversible else reader.REVERSIBLE)
                   for i in exported],
        "dataset": {"chunkCount": len(DATASET), "sha256": DATASET_SHA},
        "exported": exported,
        "reconstruction": rule or COUNT,
        "seal": {"maxClass": seal},
    }
    if contract is not None:
        body["contractId"] = contract
    return body


REV, IRR = reader.REVERSIBLE, reader.IRREVERSIBLE
Case = tuple[str, dict[str, Any], str, str, str]


def cases() -> list[Case]:
    """Every case: id, record, expected decision and reason, and what it departs from."""
    return [
        ("variant-a-below-threshold", record([0, 1], REV), "allow", "reversible_so_far",
         "control: two of five chunks out under k=3; both gates permit"),
        ("variant-a-at-crossing", record([0, 1, 2], IRR), "deny", "export_irreversible",
         "the third chunk crosses k=3 and the seal says irreversible; the "
         "composition-aware gate denies here, not at the final chunk"),
        ("variant-a-final-chunk", record([0, 1, 2, 3, 4], IRR), "deny", "export_irreversible",
         "the final chunk is denied on the same basis; the denial is not one-shot"),
        ("variant-a-max-of-labels-seal", record([0, 1, 2], REV), "deny",
         "seal_understates_composition",
         "the seal takes the maximum of the per-step labels and says reversible at the "
         "crossing chunk"),
        ("threshold-committed-after-first-chunk",
         record([0, 1], REV, rule={**COUNT, "committedAt": COMMITTED_LATE}), "deny",
         "threshold_not_precommitted",
         "k was committed thirty seconds after the first chunk left"),
        ("sets-three-chunks-no-reconstructing-set", record([0, 1, 4], REV, rule=SETS),
         "allow", "reversible_so_far",
         "control: three chunks out, but no minimal reconstructing set is complete"),
        ("sets-key-field-chunk-alone", record([3], IRR, rule=SETS), "deny",
         "export_irreversible", "one chunk out, and it carries the key field"),
        ("count-same-three-chunks", record([0, 1, 4], IRR), "deny", "export_irreversible",
         "the chunks of sets-three-chunks-no-reconstructing-set under a count rule of k=3"),
        ("sets-key-field-max-of-labels-seal", record([3], REV, rule=SETS), "deny",
         "seal_understates_composition",
         "the key-field chunk alone, sealed reversible because one chunk is under any count"),
        ("step-class-irreversible", record([0], IRR, irreversible=frozenset({0})), "deny",
         "export_irreversible",
         "control: one chunk whose own step is irreversible makes the chain irreversible"),
        ("contract-id-missing", record([0, 1], REV, contract=None), "deny",
         "contract_id_missing", "the record names no contract"),
        ("contract-id-unknown",
         record([0, 1], REV, contract=reader.CONTRACT_ID.replace("/v1", "/v0")), "deny",
         "contract_id_unknown", "the record names a contract version that does not exist"),
    ]


def generate(root: Path = ROOT) -> dict[str, Any]:
    """Write every case and the manifest, and return the manifest."""
    entries = []
    for name, body, decision, reason, edit in cases():
        directory = root / "cases" / name
        directory.mkdir(parents=True, exist_ok=True)
        files = {"record.json": _json(body)}
        for item in body["chunks"]:
            files[item["payloadFile"]] = DATASET[item["index"]]
        for filename, data in files.items():
            (directory / filename).write_bytes(data)
        entries.append({
            "composedClass": reader.composed_class(body),
            "edit": edit, "expected": {"decision": decision, "reason": reason},
            "files": {key: _sha(value) for key, value in sorted(files.items())},
            "id": name, "path": f"cases/{name}",
        })
    manifest = {
        "contractId": reader.CONTRACT_ID, "corpusDigest": _sha(_json(entries)),
        "source": SOURCE, "suite": SUITE,
        "verifierContract": "verifier record.json --json; exit 0 allow, 1 deny",
        "vectors": entries,
    }
    (root / "MANIFEST.json").write_bytes(_json(manifest))
    return manifest


def corpus_digest(manifest: dict[str, Any], root: str) -> str:
    """Recompute the digest from the committed files, not their declared hashes."""
    base = Path(root)
    entries = []
    for entry in manifest["vectors"]:
        directory = base / entry["path"]
        declared = entry["files"]
        if {p.name for p in directory.iterdir() if p.is_file()} != set(declared):
            raise ValueError(f"{entry['id']}: file set changed")
        files = {name: _sha((directory / name).read_bytes()) for name in declared}
        if files != declared:
            raise ValueError(f"{entry['id']}: file digest mismatch")
        entries.append({**entry, "files": files})
    return _sha(_json(entries))


if __name__ == "__main__":
    generate()
