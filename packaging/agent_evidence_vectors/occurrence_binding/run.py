"""Run the frozen occurrence-binding corpus and retain one report per run."""

from __future__ import annotations

import argparse
import json
import platform
import re
import shlex
import sys
from pathlib import Path
from typing import Any

from .reader import (
    AXES,
    LINK_AXES,
    NATIVE_AXES,
    NON_CLAIMS,
    MalformedInput,
    canonical,
    evaluate,
    input_pins,
    occurrence_binding,
    parse_strict,
    sha256_tag,
    summary,
)

DISTRIBUTION = "agent-evidence-vectors"
PACKAGED_CORPUS = Path(__file__).parent / "corpus"


def _revision(explicit: str | None) -> str:
    if explicit is not None:
        return explicit
    from importlib.metadata import PackageNotFoundError, version

    try:
        return f"{DISTRIBUTION}=={version(DISTRIBUTION)}"
    except PackageNotFoundError:
        raise SystemExit(
            "pass --implementation-revision <40-character commit> when running from a checkout"
        ) from None


def load_corpus(root: Path) -> tuple[Any, Any, dict[str, Any], dict[str, str]]:
    """Check every corpus member against the manifest before evaluation."""
    manifest = parse_strict((root / "manifest.json").read_bytes())
    digests: dict[str, str] = {}
    for name, pinned in manifest["members"].items():
        actual = sha256_tag((root / name).read_bytes())
        if actual != pinned:
            raise MalformedInput(f"corpus member {name} is {actual}, manifest pins {pinned}")
        digests[name] = actual
    occurrence = parse_strict((root / "occurrence.json").read_bytes())
    trust = parse_strict((root / "trust.json").read_bytes())
    cases = parse_strict((root / "cases.json").read_bytes())
    if cases.get("occurrence_binding") != occurrence_binding(occurrence):
        raise MalformedInput("cases.json is not built for this occurrence")
    pinned = input_pins(occurrence)["input_sha256"]
    held = sha256_tag(canonical(parse_strict((root / occurrence["input_file"]).read_bytes())))
    if held != pinned:
        raise MalformedInput(f"{occurrence['input_file']} is {held}, the occurrence pins {pinned}")
    return occurrence, trust, cases, digests


def run_corpus(root: Path) -> dict[str, Any]:
    """Evaluate every case, then compare with its expected answer."""
    occurrence, trust, cases, digests = load_corpus(root)
    results = []
    failures = []
    for case in cases["cases"]:
        actual = evaluate(occurrence, trust, case)
        got = summary(actual)
        if got != case["expected"]:
            failures.append(case["id"])
        results.append(
            {
                "case_id": case["id"],
                "axis": case["axis"],
                "actual": actual,
                "expected": case["expected"],
            }
        )
    return {
        "schema": "aev-occurrence-binding-report/v1",
        "occurrence_binding": cases["occurrence_binding"],
        "input_digests": digests,
        "axes": list(AXES),
        "native_axes": list(NATIVE_AXES),
        "link_axes": list(LINK_AXES),
        "non_claims": list(NON_CLAIMS),
        "non_claim_note": (
            "Settlement finality, work acceptance and the observed effect of the call are not "
            "established by any case in this corpus, whatever an artifact says about itself."
        ),
        "results": results,
        "failures": failures,
    }


def main(argv: list[str] | None = None) -> int:
    """Evaluate the corpus into a new output directory; exit 1 on any mismatch."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, default=PACKAGED_CORPUS)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--implementation-revision", default=None)
    args = parser.parse_args(argv)
    if args.implementation_revision is not None and not re.fullmatch(
        r"[0-9a-f]{40}", args.implementation_revision
    ):
        parser.error("implementation revision must be a 40-character Git commit")
    args.output.mkdir(parents=True, exist_ok=False)
    report = run_corpus(args.corpus)
    report["implementation_revision"] = _revision(args.implementation_revision)
    report["environment"] = f"Python {platform.python_version()} on {platform.platform()}"
    report["command"] = shlex.join([sys.executable, *sys.argv])
    (args.output / "report.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"cases": len(report["results"]), "failures": report["failures"]}))
    return int(bool(report["failures"]))


if __name__ == "__main__":
    raise SystemExit(main())
