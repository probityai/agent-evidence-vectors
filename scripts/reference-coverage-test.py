#!/usr/bin/env python3
"""Cases for scripts/reference-coverage.py, the per-corpus reference coverage on the shield.

    uv run --group crosscheck python scripts/reference-coverage-test.py

Exit 0 when every case behaves as described; 1 otherwise.
"""

from __future__ import annotations

import importlib.util
import json
import sys
import tomllib
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
FROZEN_ID = "https://probityai.github.io/probity/verifiers/agent-evidence-verify"


def load() -> Any:
    spec = importlib.util.spec_from_file_location(
        "aev_reference_coverage", ROOT / "scripts" / "reference-coverage.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


COVERAGE = load()


def committed_status() -> dict[str, Any]:
    return dict(json.loads((ROOT / COVERAGE.STATUS).read_text(encoding="utf-8")))


def case_a_shield_states_n_of_m_and_a_full_corpus_is_green() -> None:
    status = {
        "verifier": FROZEN_ID,
        "checked": 5,
        "total": 9,
        "corpora": [
            {"id": "a", "checked": 3, "total": 3, "disagreements": 0},
            {"id": "b", "checked": 2, "total": 6, "disagreements": 0},
        ],
    }
    files = COVERAGE.render(status)
    assert "5 of 9 members" in files[COVERAGE.SHIELD], "the overall shield does not state N of M"
    one, two = (files[COVERAGE.PER_CORPUS / f"{name}.svg"] for name in ("a", "b"))
    assert "3 of 3 members" in one and "#2ea44f" in one, "a fully covered corpus is not green"
    assert "2 of 6 members" in two and "#2ea44f" not in two, "a partly covered corpus is green"


def case_every_registered_corpus_has_a_row() -> None:
    registry = tomllib.loads((ROOT / "corpora" / "REGISTRY.toml").read_text(encoding="utf-8"))
    ids = [r["id"] for r in committed_status()["corpora"]]
    assert ids == [c["id"] for c in registry["corpus"]], (
        "the status file does not list every registered corpus, in registry order"
    )


def case_the_status_names_the_frozen_verifier_and_adds_up() -> None:
    status = committed_status()
    assert status["verifier"] == FROZEN_ID, f"the verifier id is {status['verifier']}"
    assert status["checked"] == sum(r["checked"] for r in status["corpora"])
    assert status["total"] == sum(r["total"] for r in status["corpora"])
    assert all(r["checked"] <= r["total"] for r in status["corpora"])


def case_every_corpus_has_its_own_shield() -> None:
    for row in committed_status()["corpora"]:
        shield = ROOT / COVERAGE.PER_CORPUS / f"{row['id']}.svg"
        assert shield.is_file(), f"{row['id']} has no shield"
        assert f"{row['checked']} of {row['total']} members" in shield.read_text(encoding="utf-8")


def case_the_committed_files_match_the_verifier() -> None:
    files = COVERAGE.render(COVERAGE.build_status(ROOT))
    for path, text in files.items():
        assert (ROOT / path).read_text(encoding="utf-8") == text, (
            f"{path} is stale; run scripts/reference-coverage.py"
        )


CASES = [
    case_a_shield_states_n_of_m_and_a_full_corpus_is_green,
    case_every_registered_corpus_has_a_row,
    case_the_status_names_the_frozen_verifier_and_adds_up,
    case_every_corpus_has_its_own_shield,
    case_the_committed_files_match_the_verifier,
]


def main() -> int:
    failed = 0
    for case in CASES:
        try:
            case()
            print(f"ok   {case.__name__}")
        except AssertionError as exc:
            failed += 1
            print(f"FAIL {case.__name__}: {exc}")
    print(f"{len(CASES) - failed}/{len(CASES)} cases passed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
