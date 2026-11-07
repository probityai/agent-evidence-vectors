#!/usr/bin/env python3
"""Publish, per corpus, how many members the reference verifier judges as the corpus declares.

For every corpus in corpora/REGISTRY.toml this runs the Action's reference stage logic
(scripts/action-reference-stage.py) over the corpus manifest and records N of M, the same
count the Action prints as `reference-checked conformance N of M`. A corpus with no route
through the reference verifier is recorded as 0 of M, never left out.

It writes docs/status/reference-coverage.json (one row per corpus) and the status shield
assets/badges/reference-coverage.svg, whose text is the totals, and one shield per corpus,
assets/status/reference/<corpus id>.svg, whose text is that corpus's N of M. `--check`
recomputes every file and fails when a committed one differs, so a shield cannot drift
from the verifier.

usage: reference-coverage.py [--check] [--root DIR]
Run it with the crosscheck group:
    uv run --locked --group crosscheck python scripts/reference-coverage.py
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import sys
import tomllib
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
STATUS = Path("docs/status/reference-coverage.json")
SHIELD = Path("assets/badges/reference-coverage.svg")
PER_CORPUS = Path("assets/status/reference")


def load(name: str, file: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, HERE / file)
    if spec is None or spec.loader is None:
        sys.exit(f"reference-coverage: cannot load {file}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def corpus_row(stage: Any, crosscheck: Any, root: Path, corpus: dict[str, Any]) -> dict[str, Any]:
    directory = root / corpus["path"]
    document = json.loads((directory / "MANIFEST.json").read_text(encoding="utf-8"))
    entries = document["vectors"]
    if document.get("predicateType") == stage.AEE_PREDICATE:
        checked, total, notes = stage.aee_tally(entries, directory)
    else:
        checked, total, notes = stage.tally(entries, directory, crosscheck)
    return {"id": corpus["id"], "checked": checked, "total": total, "disagreements": len(notes)}


def build_status(root: Path) -> dict[str, Any]:
    stage = load("aev_reference_stage", "action-reference-stage.py")
    crosscheck = stage.load_crosscheck()
    registry = tomllib.loads((root / "corpora" / "REGISTRY.toml").read_text(encoding="utf-8"))
    rows = [corpus_row(stage, crosscheck, root, c) for c in registry["corpus"]]
    return {
        "verifier": stage.reference_id(),
        "checked": sum(r["checked"] for r in rows),
        "total": sum(r["total"] for r in rows),
        "corpora": rows,
    }


def shield_svg(checked: int, total: int, color: str) -> str:
    badge = load("aev_make_badge", "make-badge.py")
    return str(badge.build(f"{checked} of {total} members", "reference-checked", color, None))


def render(status: dict[str, Any]) -> dict[Path, str]:
    files = {
        STATUS: json.dumps(status, indent=2) + "\n",
        SHIELD: shield_svg(status["checked"], status["total"], "#007ec6"),
    }
    for row in status["corpora"]:
        full = bool(row["total"]) and row["checked"] == row["total"]
        files[PER_CORPUS / f"{row['id']}.svg"] = shield_svg(
            row["checked"], row["total"], "#2ea44f" if full else "#9f9f9f"
        )
    return files


def same(path: Path, text: str) -> bool:
    return path.is_file() and path.read_text(encoding="utf-8") == text


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--root", type=Path, default=ROOT)
    args = ap.parse_args(argv)
    files = render(build_status(args.root))
    stale = [p for p, text in files.items() if not same(args.root / p, text)]
    if args.check:
        if stale:
            print("reference-coverage: stale, run scripts/reference-coverage.py: "
                  + ", ".join(str(p) for p in stale))
            return 1
        print("reference-coverage: the status files match the verifier")
        return 0
    for path, text in files.items():
        (args.root / path).parent.mkdir(parents=True, exist_ok=True)
        (args.root / path).write_text(text, encoding="utf-8")
    print(f"reference-coverage: wrote {', '.join(str(p) for p in files)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
