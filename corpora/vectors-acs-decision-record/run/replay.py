"""Replay every member's disclosed context and policy through agent-control-spec.

This is what a distrusting consumer does: it does not take the record's verdict or the
corpus's replayedVerdict on trust. It evaluates the disclosed manifest and bundle on the
disclosed context with the named runtime and compares. Members whose disclosed bytes
were edited (the input and policy digest rejects) are expected to replay differently.

    uv run python replay.py
"""

# The imports below resolve only in this directory's own pinned environment (pyproject.toml
# and uv.lock here), which the repository's type-check environment deliberately does not install.
# pyright: reportMissingImports=false

from __future__ import annotations

import json
import sys
from pathlib import Path

from agent_control_spec import ActivatedPolicy

CORPUS = Path(__file__).resolve().parent.parent
EDITED_DISCLOSURE = ("input-digest-mismatch", "policy-digest-mismatch")


def main() -> int:
    manifest = json.loads((CORPUS / "MANIFEST.json").read_text(encoding="utf-8"))
    unexpected = 0
    for entry in manifest["vectors"]:
        member = json.loads((CORPUS / entry["path"]).read_text(encoding="utf-8"))
        disc = member["disclosed"]
        policy = ActivatedPolicy.from_memory(disc["manifest"], {"tool_gate": disc["policyBundle"]})
        replayed = policy.evaluate("pre_tool_call", disc["context"]).to_wire()
        same = replayed == member["replayedVerdict"]
        if not same and entry["expected"]["code"] not in EDITED_DISCLOSURE:
            unexpected += 1
        print(f"{entry['id']}: replay {replayed} {'==' if same else '!='} replayedVerdict")
    print(f"replay: {len(manifest['vectors'])} members, {unexpected} unexpected mismatches")
    return 1 if unexpected else 0


if __name__ == "__main__":
    sys.exit(main())
