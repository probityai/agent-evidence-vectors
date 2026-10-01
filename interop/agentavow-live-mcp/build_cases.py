"""Rebuild the synthetic named-tool captures without running the reader."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
from pathlib import Path

from run_vectors import jcs_dumps

ROOT = Path(__file__).resolve().parent
PROFILE = "agentavow.mcp-tool-definition.v1"
ENDPOINT = "https://example.test/mcp"
PRIMARY = {
    "name": "approve_invoice",
    "description": "Approve a draft invoice after review.",
    "inputSchema": {"type": "object", "properties": {"invoiceId": {"type": "string"}}},
    "annotations": {"readOnlyHint": False},
}
SECONDARY = {"name": "list_invoices", "description": "List drafts.", "inputSchema": {"type": "object"}}


def content() -> bytes:
    selected = {key: PRIMARY[key] for key in (
        "name", "title", "description", "inputSchema", "outputSchema", "annotations"
    ) if PRIMARY.get(key) is not None}
    digest = "sha256:" + hashlib.sha256(jcs_dumps({"profile": PROFILE, "tool": selected})).hexdigest()
    pin = {"endpoint": ENDPOINT, "toolName": PRIMARY["name"], "toolDigest": digest}
    cases = []

    def add(label: str, tools: list[dict], endpoint: str = ENDPOINT) -> None:
        cases.append({"name": label, "capture": {"endpoint": endpoint, "tools": tools}})

    add("unchanged", [PRIMARY, SECONDARY])
    add("reordered", [SECONDARY, PRIMARY])
    metadata = {**PRIMARY, "_meta": {"requestId": "new"}}
    add("metadata-only", [metadata, SECONDARY])
    description = {**PRIMARY, "description": "Approve any invoice without review."}
    add("changed-description", [description, SECONDARY])
    schema = copy.deepcopy(PRIMARY)
    schema["inputSchema"]["properties"]["amount"] = {"type": "number"}
    add("changed-schema", [schema, SECONDARY])
    add("changed-other-tool", [PRIMARY, {**SECONDARY, "description": "List all records."}])
    add("duplicate-name", [PRIMARY, description, SECONDARY])
    add("missing-name", [SECONDARY])
    add("other-endpoint", [PRIMARY, SECONDARY], "https://other.example.test/mcp")
    nonportable = copy.deepcopy(PRIMARY)
    nonportable["inputSchema"]["properties"]["amount"] = {"minimum": 0.25}
    add("fractional-number", [nonportable, SECONDARY])
    return (json.dumps({"pin": pin, "cases": cases}, indent=2, ensure_ascii=False) + "\n").encode()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    target = ROOT / "fixtures" / "cases.json"
    generated = content()
    if args.check:
        if target.read_bytes() != generated:
            raise SystemExit("fixture differs")
        print("fixture matches")
    else:
        target.parent.mkdir(exist_ok=True)
        target.write_bytes(generated)
