#!/usr/bin/env python3
"""Tests for scripts/predicate-registry-gate.py, each asserting a refusal.

The gate exists because a URI carried only inside a signed payload was invisible
to review, so the case it must catch is that one: an unregistered URI that
appears nowhere as text. Each case builds a throwaway git repository and runs
the real script against it.
"""

from __future__ import annotations

import base64
import json
import subprocess
import sys
import tempfile
from pathlib import Path

GATE = Path(__file__).resolve().parent / "predicate-registry-gate.py"
# Built from parts so this file does not itself carry a URI the gate would read
# when it scans this repository.
PREFIX = "https://probityai.github.io/agent-evidence-vectors/" + "predicate/"


def registry(*names: str) -> str:
    body = "".join(f"### `predicate/{name}`\n\n- Status: test.\n\n" for name in names)
    return "# Predicate types this host answers for\n\n## Defined here\n\n" + body


def signed_member(name: str) -> str:
    statement = json.dumps({"predicateType": PREFIX + name, "predicate": {"k": "v" * 40}})
    payload = base64.b64encode(statement.encode()).decode()
    envelope = json.dumps({"payloadType": "application/vnd.in-toto+json", "payload": payload})
    # Quoted inside a JSON string, the way the GovOps members carry it.
    return json.dumps({"records": [{"form": "dsse", "text": envelope}]})


def run(files: dict[str, str]) -> subprocess.CompletedProcess[str]:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        subprocess.run(["git", "init", "-q", str(root)], check=True)
        for relative, text in files.items():
            target = root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(text, encoding="utf-8")
        subprocess.run(["git", "-C", str(root), "add", "-A"], check=True)
        return subprocess.run(
            [sys.executable, str(GATE), "--root", str(root)],
            capture_output=True,
            text=True,
        )


def check(label: str, result: subprocess.CompletedProcess[str], code: int, needle: str) -> bool:
    output = result.stdout + result.stderr
    ok = result.returncode == code and needle in output
    print(f"{'ok' if ok else 'FAIL'}: {label} (exit {result.returncode})")
    if not ok:
        print(output)
    return ok


def main() -> int:
    results = [
        check(
            "a URI carried only inside a signed payload and not registered is refused",
            run(
                {
                    "spec/predicates/REGISTRY.md": registry("v1/known"),
                    "a/README.md": f"Type: {PREFIX}v1/known\n",
                    "a/members/m.json": signed_member("v1/hidden"),
                }
            ),
            1,
            PREFIX + "v1/hidden",
        ),
        check(
            "a URI written only as text and not registered is refused",
            run(
                {
                    "spec/predicates/REGISTRY.md": registry("v1/known"),
                    "a/README.md": f"Type: {PREFIX}v1/known and {PREFIX}v1/plain\n",
                }
            ),
            1,
            PREFIX + "v1/plain",
        ),
        check(
            "a tree with no URI under the prefix is refused as a broken read",
            run({"spec/predicates/REGISTRY.md": registry("v1/known"), "a.txt": "none\n"}),
            1,
            "broken read",
        ),
        check(
            "every URI registered, including one inside a signed payload, passes",
            run(
                {
                    "spec/predicates/REGISTRY.md": registry("v1/known", "v1/hidden"),
                    "a/README.md": f"Type: {PREFIX}v1/known\n",
                    "a/members/m.json": signed_member("v1/hidden"),
                }
            ),
            0,
            "1 of them inside signed payloads",
        ),
    ]
    return 0 if all(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
