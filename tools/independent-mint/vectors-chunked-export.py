"""Re-mint corpora/vectors-chunked-export from its published case table and composition rule.

    python -E -s -S vectors-chunked-export.py OUT

A second generator: it shares no code with the corpus generator or the reader, so the
``composedClass`` of every case is recomputed here from the rule the README states (a chain
is irreversible when one of its steps is, or when the committed reconstruction rule holds
over the chunks exported so far: at least ``k`` of them for a count rule, every chunk of one
minimal set for a sets rule) and not read from the reader that the corpus tests.
"""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path
from typing import Any

from _layout import pretty, write_case, write_manifest

CONTRACT = "https://probityai.github.io/agent-evidence-vectors/contract/chunked-export/v1"
REV, IRR = "reversible", "irreversible"
FIRST_COMMIT = "2026-10-10T10:59:00Z"
LATE_COMMIT = "2026-10-10T11:00:30Z"
COUNT_RULE = {"committedAt": FIRST_COMMIT, "k": 3, "kind": "count"}
SETS_RULE = {"committedAt": FIRST_COMMIT, "kind": "sets", "minimalSets": [[0, 1, 2], [3]]}


def dataset() -> list[bytes]:
    """The five chunks of the flagged dataset, one JSON line each."""
    lines = []
    for index in range(5):
        low, high = index * 100, index * 100 + 99
        lines.append(f'{{"chunk":{index},"rows":"flagged-dataset rows {low}-{high}"}}\n'.encode())
    return lines


CHUNKS = dataset()


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def export_record(
    exported: list[int],
    seal: str,
    rule: dict[str, Any] | None = None,
    irreversible_steps: tuple[int, ...] = (),
    contract: str | None = CONTRACT,
) -> dict[str, Any]:
    """The record an export gate sees when the chunks in ``exported`` have left."""
    record: dict[str, Any] = {
        "chunks": [
            {
                "index": index,
                "leftAt": f"2026-10-10T11:0{index}:00Z",
                "payloadFile": f"chunk-{index}.bin",
                "payloadSha256": sha(CHUNKS[index]),
                "stepClass": IRR if index in irreversible_steps else REV,
            }
            for index in exported
        ],
        "dataset": {"chunkCount": len(CHUNKS), "sha256": sha(b"".join(CHUNKS))},
        "exported": exported,
        "reconstruction": rule if rule is not None else COUNT_RULE,
        "seal": {"maxClass": seal},
    }
    if contract is not None:
        record["contractId"] = contract
    return record


def composition(record: dict[str, Any]) -> str:
    """The class of the export chain, from the README's rule."""
    if any(chunk["stepClass"] == IRR for chunk in record["chunks"]):
        return IRR
    out = set(record["exported"])
    rule = record["reconstruction"]
    if rule["kind"] == "count":
        return IRR if len(out) >= rule["k"] else REV
    return IRR if any(out.issuperset(group) for group in rule["minimalSets"]) else REV


def table() -> list[tuple[str, dict[str, Any], str, str, str]]:
    """The README's case table: name, record, decision, reason, the edit it makes."""
    late = {**COUNT_RULE, "committedAt": LATE_COMMIT}
    old_contract = CONTRACT.replace("/v1", "/v0")
    return [
        ("variant-a-below-threshold", export_record([0, 1], REV), "allow", "reversible_so_far",
         "control: two of five chunks out under k=3; both gates permit"),
        ("variant-a-at-crossing", export_record([0, 1, 2], IRR), "deny", "export_irreversible",
         "the third chunk crosses k=3 and the seal says irreversible; the "
         "composition-aware gate denies here, not at the final chunk"),
        ("variant-a-final-chunk", export_record([0, 1, 2, 3, 4], IRR), "deny",
         "export_irreversible",
         "the final chunk is denied on the same basis; the denial is not one-shot"),
        ("variant-a-max-of-labels-seal", export_record([0, 1, 2], REV), "deny",
         "seal_understates_composition",
         "the seal takes the maximum of the per-step labels and says reversible at the "
         "crossing chunk"),
        ("threshold-committed-after-first-chunk", export_record([0, 1], REV, rule=late), "deny",
         "threshold_not_precommitted", "k was committed thirty seconds after the first chunk left"),
        ("sets-three-chunks-no-reconstructing-set", export_record([0, 1, 4], REV, rule=SETS_RULE),
         "allow", "reversible_so_far",
         "control: three chunks out, but no minimal reconstructing set is complete"),
        ("sets-key-field-chunk-alone", export_record([3], IRR, rule=SETS_RULE), "deny",
         "export_irreversible", "one chunk out, and it carries the key field"),
        ("count-same-three-chunks", export_record([0, 1, 4], IRR), "deny", "export_irreversible",
         "the chunks of sets-three-chunks-no-reconstructing-set under a count rule of k=3"),
        ("sets-key-field-max-of-labels-seal", export_record([3], REV, rule=SETS_RULE), "deny",
         "seal_understates_composition",
         "the key-field chunk alone, sealed reversible because one chunk is under any count"),
        ("step-class-irreversible", export_record([0], IRR, irreversible_steps=(0,)), "deny",
         "export_irreversible",
         "control: one chunk whose own step is irreversible makes the chain irreversible"),
        ("contract-id-missing", export_record([0, 1], REV, contract=None), "deny",
         "contract_id_missing", "the record names no contract"),
        ("contract-id-unknown", export_record([0, 1], REV, contract=old_contract), "deny",
         "contract_id_unknown", "the record names a contract version that does not exist"),
    ]  # fmt: skip


def mint(out: Path) -> None:
    """Write the corpus under ``out``."""
    entries = []
    for name, record, decision, reason, edit in table():
        files = {"record.json": pretty(record)}
        for chunk in record["chunks"]:
            files[chunk["payloadFile"]] = CHUNKS[chunk["index"]]
        entries.append(
            {
                "composedClass": composition(record),
                "edit": edit,
                "expected": {"decision": decision, "reason": reason},
                "files": write_case(out, name, files),
                "id": name,
                "path": "cases/" + name,
            }
        )
    source = {
        "author": "Mayur021",
        "thread": "https://github.com/probityai/agent-evidence/issues/24#issuecomment-6247271570",
        "variant": "Variant A, boundary B2",
    }
    write_manifest(
        out,
        entries,
        contractId=CONTRACT,
        source=source,
        suite="chunked-export/v1",
        verifierContract="verifier record.json --json; exit 0 allow, 1 deny",
    )


if __name__ == "__main__":
    mint(Path(sys.argv[1]))
