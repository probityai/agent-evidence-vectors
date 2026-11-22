"""Run the holder-bound-credential cases through the reference reader or a named verifier."""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "packaging"))

from agent_evidence_vectors.holderbound import check, main, verify  # noqa: E402, F401


def corpus_json() -> int:
    """Print every case's decision as one JSON object, for the intake record."""
    root = Path(__file__).resolve().parent
    manifest = json.loads((root / "MANIFEST.json").read_text(encoding="utf-8"))
    members = []
    for entry in sorted(manifest["vectors"], key=lambda e: e["id"]):
        answer = verify(root / entry["path"] / "record.json")
        members.append({"id": entry["id"], "kind": "accept" if answer["decision"] == "accept" else "reject"})
    print(json.dumps({"suite": manifest["suite"], "dir": root.name, "members": members},
                     sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    args = sys.argv[1:]
    raise SystemExit(corpus_json() if args == ["--json"] else main())
