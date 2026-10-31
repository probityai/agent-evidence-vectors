"""Export exact raw rows and narrowly scoped Verify operand-lineage cases."""

from __future__ import annotations

from pathlib import Path

from .reader import InputError, canonical, digest


def _write(path: Path, data: bytes) -> dict:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return {"path": path.name, "sha256": digest(data), "length": len(data)}


def verify_projection(row: dict) -> tuple[dict, dict, dict]:
    """Project integer token operands; the importer separately checks raw-row lineage."""
    tokens = row["comparison"]["tokens"]
    if tokens["delta"] is None:
        raise InputError("token operands are unavailable")
    before, after, delta = (str(tokens[key]) for key in ("before", "after", "delta"))
    source = {"values": {"before_total": before, "after_total": after}}
    execution = {
        "steps": [
            {
                "id": "token_delta",
                "operation": "subtract",
                "operands": [
                    {"kind": "source", "ref": "after_total", "value": after},
                    {"kind": "source", "ref": "before_total", "value": before},
                ],
                "result": delta,
            }
        ],
        "figure": delta,
    }
    lineage = {
        "scope": "Importer-derived token projection, not an independently captured execution trace.",
        "before_total": {**row["lineage"]["before"], "pointer": row["lineage"]["before"]["pointer"] + "/s004/total"},
        "after_total": {**row["lineage"]["after"], "pointer": "/row/s004/total"},
    }
    return source, execution, lineage


def write_bundle(result: dict, raw: dict[str, bytes], manifest: dict, output: Path) -> dict:
    """Keep publisher row bytes exact; source implementation remains fetch-by-pin."""
    if output.exists() and (not output.is_dir() or any(output.iterdir())):
        raise InputError("output must be absent or empty")
    output.mkdir(parents=True, exist_ok=True)
    row_bindings = {}
    for role, data in raw.items():
        if role in {"baseline_state", "current_state"} or role.startswith("run/"):
            label = role.replace("/", "-") + ".json"
            row_bindings[role] = _write(output / "raw" / label, data) | {"path": "raw/" + label}
    _write(output / "source-pins.json", canonical(manifest))
    _write(output / "import.json", canonical(result))
    bridge = []
    for row in result["rows"]:
        if row["comparison"]["tokens"]["delta"] is None:
            bridge.append({"harness": row["harness"], "status": "not_established", "reason": "token-operands-unavailable"})
            continue
        source, execution, lineage = verify_projection(row)
        folder = output / "verify" / row["harness"]
        source_binding = _write(folder / "source.json", canonical(source))
        execution_binding = _write(folder / "execution.json", canonical(execution))
        case_id = "watch-token-delta-" + row["harness"]
        case = {
            "schema_version": "probity-case/v1",
            "case_id": case_id,
            "artifacts": {"source": source_binding, "execution": execution_binding},
        }
        policy = {
            "schema_version": "probity-policy/v1",
            "witnesses": {
                role: {"artifact": role, "sha256": binding["sha256"], "authority": "Importer operator's selected publisher-row projection"}
                for role, binding in (("source", source_binding), ("execution", execution_binding))
            },
            "assessments": {
                case_id: {
                    "claim_type": "operand_lineage/v1",
                    "source_witness": "source",
                    "execution_witness": "execution",
                    "final_step": "token_delta",
                    "constants": {},
                }
            },
        }
        _write(folder / "case.json", canonical(case))
        _write(folder / "candidate-policy.json", canonical(policy))
        _write(folder / "raw-row-lineage.json", canonical(lineage))
        bridge.append(
            {
                "harness": row["harness"],
                "status": "ready",
                "case": f"verify/{row['harness']}/case.json",
                "candidate_policy": f"verify/{row['harness']}/candidate-policy.json",
            }
        )
    index = {
        "schema": "probity.watch-bundle/v1",
        "raw_rows": row_bindings,
        "verify_bridge": bridge,
        "verify_revision": manifest.get("verify", {}).get("revision"),
        "policy_status": "Generated candidate policies; recipient acceptance is separate.",
        "implementation_bytes": "Fetched source definitions are hash-bound but not redistributed in this row bundle.",
    }
    _write(output / "bundle.json", canonical(index))
    return index
