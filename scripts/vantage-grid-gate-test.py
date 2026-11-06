#!/usr/bin/env python3
"""The vantage-grid gate passes the published page and fails each mutation of it."""

from __future__ import annotations

import importlib.util
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "vantage_grid_gate", ROOT / "scripts" / "vantage-grid-gate.py"
)
assert SPEC is not None and SPEC.loader is not None
gate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gate)

PAGE = ROOT / "docs" / "reference" / "vantage-grid.md"
TEXT = PAGE.read_text(encoding="utf-8")
DSSE = "https://github.com/secure-systems-lab/dsse/blob/b531b787bb3e5f0c3e1c19cee84da1c5d569b061/protocol.md"
SRR = (
    "../../corpora/vectors-self-reported-record/README.md#the-five-attacks-and-where-each-one-went"
)

MUTATIONS = {
    "a cell loses its only link": (f"([DSSE protocol]({DSSE}))", ""),
    "a relative link names no file": (
        "(../guides/airgap-enclave.md)",
        "(../guides/no-such-page.md)",
    ),
    "a fragment names no heading": (SRR, SRR.replace("five-attacks", "six-attacks")),
    "an external link leaves the allowed hosts": (DSSE, "https://example.com/protocol.md"),
    "a github link is not pinned": (
        DSSE,
        DSSE.replace("b531b787bb3e5f0c3e1c19cee84da1c5d569b061", "master"),
    ),
    "plain http": (
        "https://www.rfc-editor.org/rfc/rfc9334.html",
        "http://www.rfc-editor.org/rfc/rfc9334.html",
    ),
    "a row is renamed": ("| Observability trace |", "| OpenTelemetry |"),
    "the column is reworded": (
        "| Produced by an observer the agent cannot reach |",
        "| Produced by an observer |",
    ),
    "a verdict is hedged": ("| No |\n| Vendor", "| Partly |\n| Vendor"),
}


def run_on(text: str) -> int:
    # The page's relative links resolve from its own directory, so a mutated
    # copy is written beside the original rather than into a bare temp dir.
    with tempfile.NamedTemporaryFile(
        "w", suffix=".md", dir=PAGE.parent, delete=False, encoding="utf-8"
    ) as handle:
        handle.write(text)
        path = Path(handle.name)
    try:
        return int(gate.main(["--page", str(path)]))
    finally:
        path.unlink()


def main() -> int:
    failed = 0
    if gate.main(["--page", str(PAGE)]) != 0:
        print("FAIL the published page does not pass")
        failed += 1
    for name, (old, new) in MUTATIONS.items():
        if old not in TEXT:
            print(f"FAIL mutation {name!r}: anchor text not on the page")
            failed += 1
            continue
        code = run_on(TEXT.replace(old, new, 1))
        if code != 1:
            print(f"FAIL mutation {name!r} exited {code}, expected 1")
            failed += 1
    if (
        gate.slug("The five attacks, and where each one went")
        != "the-five-attacks-and-where-each-one-went"
    ):
        print("FAIL slug rule")
        failed += 1
    print(f"vantage-grid-gate-test: {len(MUTATIONS)} mutations, {failed} failures")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
