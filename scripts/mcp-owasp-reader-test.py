#!/usr/bin/env python3
"""Prove the OWASP MCP corpus reader refuses what it exists to refuse.

Each case breaks one thing and asserts the packaged reader notices: every rule
disabled in turn must free exactly its own reject member, an edited record must
lose its identifier, a threat whose testing requirement disappears must be
named, and a renumbered identifier must be refused.
"""

from __future__ import annotations

import json
import shutil
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "packaging"))

from agent_evidence_vectors import mcpowasp  # noqa: E402

CORPUS = REPO / "vectors-mcp-owasp"


def failing(judged: mcpowasp.Judged) -> list[str]:
    return [m.id for m in judged.members if m.findings]


def copy_corpus() -> Path:
    target = Path(tempfile.mkdtemp()) / "vectors-mcp-owasp"
    shutil.copytree(CORPUS, target)
    return target


def main() -> int:
    errors: list[str] = []
    clean = mcpowasp.judge(CORPUS)
    if not clean.ok():
        errors.append("the committed corpus does not judge clean:\n" + mcpowasp.render(clean))

    manifest = json.loads((CORPUS / "MANIFEST.json").read_text())
    rejects = {
        json.loads((CORPUS / v["record"]).read_text())["requirement"]: v["id"]
        for v in manifest["vectors"]
        if v["kind"] == "reject"
    }
    for requirement, original in list(mcpowasp.RULES.items()):
        mcpowasp.RULES[requirement] = lambda _o: None
        try:
            freed = failing(mcpowasp.judge(CORPUS))
        finally:
            mcpowasp.RULES[requirement] = original
        if freed != [rejects[requirement]]:
            errors.append(
                f"disabling {requirement} freed {freed}, not exactly {rejects[requirement]}"
            )

    edited = copy_corpus()
    first = manifest["vectors"][0]
    record = json.loads((edited / first["record"]).read_text())
    record["observation"]["edited"] = True
    (edited / first["record"]).write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
    judged = mcpowasp.judge(edited)
    if first["id"] not in failing(judged) or "corpusDigest" not in " ".join(judged.findings):
        errors.append("an edited record kept its identifier or the corpus digest")

    for mutate, expect in (
        (lambda r: r["threats"][7].__setitem__("testedBy", []), "MCPTM-8 names no requirement"),
        (lambda r: r["requirements"][11].__setitem__("id", "MCPVS-13"), "not minted as 1..12"),
    ):
        broken = copy_corpus()
        registry = json.loads((broken / "REGISTRY.json").read_text())
        mutate(registry)
        (broken / "REGISTRY.json").write_text(json.dumps(registry, indent=2) + "\n")
        found = " | ".join(mcpowasp.judge(broken).findings)
        if expect not in found:
            errors.append(f"a broken registry was not refused with {expect!r}: {found}")

    for line in errors:
        print("FAIL", line)
    if errors:
        return 1
    print(
        f"OK {len(mcpowasp.RULES)} rules each free exactly their own reject member; "
        "edits, unmapped threats and renumbering are refused"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
