#!/usr/bin/env python3
"""Hold docs/guides/offline-verify.md to the files it tells a reader to run.

* Every line of the page's ``sh`` blocks appears verbatim in connected.sh or
  offline.sh, so the recorded run executed what the page says.
* The page's verdict-code table names exactly the codes in
  docs/reference/receipt-verdict-codes.json, and each code's example record is
  the vector the registry names for it.
* The verifier pin in requirements.txt is the version the page states, every
  requirement carries hashes, and SHA256SUMS covers every example record.
* Every transcript (TRANSCRIPT.txt and each TRANSCRIPT-<interpreter>-<arch>.txt
  beside it) was taken with --network none, reached no index, installed the
  pinned version and printed every summary line the page quotes, and the page
  names each one.

Exit 0 when all hold; 1 with each failure named.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PAGE = ROOT / "docs" / "guides" / "offline-verify.md"
FOLDER = ROOT / "docs" / "guides" / "offline-verify"
REGISTRY = ROOT / "docs" / "reference" / "receipt-verdict-codes.json"


def blocks(text: str, lang: str) -> list[str]:
    return re.findall(rf"```{lang}\n(.*?)```", text, re.S)


def check_commands(page: str) -> list[str]:
    scripts = (FOLDER / "connected.sh").read_text() + (FOLDER / "offline.sh").read_text()
    script_lines = {line.strip() for line in scripts.splitlines()}
    return [f"page command not in connected.sh or offline.sh: {line}"
            for block in blocks(page, "sh") for line in block.splitlines()
            if line.strip() and line.strip() not in script_lines]


def check_codes(page: str) -> tuple[list[str], dict[str, str]]:
    registry = json.loads(REGISTRY.read_text(encoding="utf-8"))
    row = r"^\| `([A-Z_]+)` \| (?:failure|limit) \| .*?\| `(v[0-9a-f]{16})`"
    rows = dict(re.findall(row, page, re.M))
    want = {c["code"]: c["vector"] for c in registry["codes"]}
    if rows != want:
        table = sorted(rows.items())
        return [f"verdict-code table {table} != registry {sorted(want.items())}"], want
    return [], want


def check_pins(page: str, want: dict[str, str]) -> tuple[list[str], str | None]:
    fails = []
    req = (FOLDER / "requirements.txt").read_text(encoding="utf-8")
    pin = re.search(r"^agent-evidence-verify==(\S+) \\", req, re.M)
    version = pin.group(1) if pin else None
    if version is None or f"`agent-evidence-verify` {version}" not in page:
        fails.append("requirements.txt pin and the page's stated version differ")
    for name in re.findall(r"^([a-z0-9-]+)==", req, re.M):
        if not re.search(rf"^{name}==[^\n]*\\\n\s+--hash=sha256:", req, re.M):
            fails.append(f"requirements.txt: {name} carries no hash")
    sums = {line.split()[1] for line in (FOLDER / "SHA256SUMS").read_text().splitlines()}
    fails += [f"SHA256SUMS lacks {vid}.json" for vid in set(want.values()) | {"vfcb846afff2d6979"}
              if f"{vid}.json" not in sums]
    return fails, version


def check_transcript(page: str, version: str | None, path: Path) -> list[str]:
    name = path.name
    if f"({name})" not in page and f"[{name}]" not in page:
        return [f"page does not link {name}"]
    transcript = path.read_text(encoding="utf-8")
    stage2 = transcript.split("## stage 2: container started with --network none", 1)
    if len(stage2) != 2:
        return [f"{name} has no --network none stage"]
    fails = []
    offline = stage2[1]
    if "interfaces: lo \n" not in offline or "network probe: no route" not in offline:
        fails.append(f"{name}: offline stage shows a network interface or a reached index")
    if version is None or f"agent-evidence-verify-{version}" not in offline:
        fails.append(f"{name}: did not install the pinned verifier offline")
    lines = offline.splitlines()
    fails += [f"{name}: quoted summary line not in transcript: {line}"
              for block in blocks(page, "text") for line in block.splitlines()
              if line.strip() and line not in lines]
    return fails


def check() -> list[str]:
    page = PAGE.read_text(encoding="utf-8")
    fails = check_commands(page)
    code_fails, want = check_codes(page)
    pin_fails, version = check_pins(page, want)
    transcripts = sorted(FOLDER.glob("TRANSCRIPT*.txt"))
    transcript_fails = [f for t in transcripts for f in check_transcript(page, version, t)]
    if not transcripts:
        transcript_fails = ["no TRANSCRIPT.txt"]
    return fails + code_fails + pin_fails + transcript_fails


def main() -> int:
    fails = check()
    for line in fails:
        print("FAIL:", line)
    if not fails:
        print("offline-verify page: commands, codes, pins and transcript agree")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
