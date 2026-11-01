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
from collections.abc import Callable
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "packaging"))

from agent_evidence_vectors import mcpowasp  # noqa: E402

CORPUS = REPO / "corpora" / "vectors-mcp-owasp"


def failing(judged: mcpowasp.Judged) -> list[str]:
    return [m.id for m in judged.members if m.findings]


def copy_corpus() -> Path:
    target = Path(tempfile.mkdtemp()) / "corpora" / "vectors-mcp-owasp"
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

    errors.extend(float_cases(manifest))

    mutations: list[tuple[Callable[[dict[str, Any]], None], str]] = [
        (lambda r: r["threats"][7].__setitem__("testedBy", []), "MCPTM-8 names no requirement"),
        (lambda r: r["requirements"][11].__setitem__("id", "MCPVS-13"), "not minted as 1..12"),
    ]
    for mutate, expect in mutations:
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


def float_cases(manifest: dict[str, Any]) -> list[str]:
    """A float inside a digested record is refused, as the Go reader refuses it.

    The Go reader digests through corpusreaders/pyjson.go, which refuses a number token
    with a fraction or an exponent. This reader used to digest the float with
    repr, so the two parted on any record that carried one. Here a float in a
    record must cost it its identifier, and a float inside a stream the
    tamper-evidence rule hashes must be named, token as written, in the reason.
    """
    errors: list[str] = []
    edited = copy_corpus()
    first = manifest["vectors"][0]
    path = edited / first["record"]
    path.write_text(path.read_text().replace('"observation": {', '"observation": {"x": 2.50, ', 1))
    record = mcpowasp.load_record(path.read_bytes())
    try:
        mcpowasp.identify(first["kind"], first["conditions"], record)
        errors.append("a record carrying a float was given an identifier")
    except mcpowasp.FloatRefused as exc:
        if "2.50 is a JSON float" not in str(exc):
            errors.append(f"the float refusal does not name the token as written: {exc}")
    if first["id"] not in failing(mcpowasp.judge(edited)):
        errors.append("a record carrying a float kept its identifier")

    streamed = copy_corpus()
    entry = next(e for e in manifest["vectors"]
                 if e["conditions"] == ["MCPVS-9"] and e["kind"] == "accept")
    path = streamed / entry["record"]
    record = json.loads(path.read_text())
    record["observation"]["stream"][0]["cost"] = "@@FLOAT@@"
    text = json.dumps(record, indent=2, sort_keys=True).replace('"@@FLOAT@@"', "1e-7")
    path.write_text(text + "\n")
    judged = mcpowasp.judge(streamed)
    found = " | ".join(f for m in judged.members if m.id == entry["id"] for f in m.findings)
    if "the record stream cannot be hashed: corpora: 1e-7 is a JSON float" not in found:
        errors.append(f"a float inside the hashed stream was not refused by name: {found}")
    return errors


if __name__ == "__main__":
    raise SystemExit(main())
