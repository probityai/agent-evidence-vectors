"""Re-encode R6's posted records.v0.1.json into the v0.1 report shape.

No check is re-run and no value is added. Every reader slot is moved from the
posted field that already holds it; the one computed value is the check-set
digest, which is a function of the moved checks. Fields no reader reads are
kept verbatim under their posted names.

    python3 -I reencode_r6.py posted-records.v0.1.json --out report-v01.json

Standard library plus this repository's reference reader (for the check-set
root and the closing read). Exits 1 if the posted file is not the pinned one,
if its counts disagree with its records, or if the reader rejects the output.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "packaging"))
from agent_evidence_vectors import w3creport  # noqa: E402

#: records.v0.1.json at Rul1an/assay 0e59b404 and 8a385471 (the R6 pins),
#: docs/experiments/approval-freshness-discrimination-2026-09/w3c-v0.1/.
POSTED_SHA256 = "d81ea91d012c6912701fc0fcbb10458d3496f459f400f49516dd77d4d33bf4e7"
SOURCE = {
    "repository": "Rul1an/assay",
    "commits": [
        "0e59b404cef6df315aac377b65ae619b4c5e4890",
        "8a38547143d42f152c3a46d76b2c026b601ae354",
    ],
    "path": "docs/experiments/approval-freshness-discrimination-2026-09/w3c-v0.1/records.v0.1.json",
    "sha256": POSTED_SHA256,
}
#: Posted fields the re-encoding consumes. Everything else is kept verbatim.
CONSUMED = ("format", "records", "rollup")
TREE_SHAPE = "flat"


class Refused(Exception):
    pass


def _claim(posted: dict[str, Any]) -> dict[str, Any]:
    return {
        "population": posted["population"],
        "claim": "satisfied" if posted["satisfied"] else "not-satisfied",
    }


def _checks(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "check": r["check_id"],
            "state": r["state"],
            "other-verdict": {"value": r["other_verdict"]},
            "discrimination": {"value": r["discrimination"]},
        }
        for r in records
    ]


def _rollup(posted: dict[str, Any], checks: list[dict[str, Any]]) -> dict[str, Any]:
    agg = posted["aggregate"]
    counts = w3creport._counts(checks)  # noqa: SLF001 - the reader's own tally
    stated = {"declared": agg["count"], "exercised": agg["count"],
              **{s: agg[s] for s in ("pass", "fail", "inconclusive", "void")}}
    if any(counts[k] != v for k, v in stated.items()) or counts["not-exercised"] != 0:
        raise Refused(f"posted aggregate {stated} disagrees with the records {counts}")
    cvr = posted["carried_vs_referenced"]
    comp = posted["completeness"]
    return dict(
        counts,
        carried=cvr["carried"],
        referenced=cvr["referenced"],
        **{"negative-capable": {"kind": posted["discriminating_power"]["answer"]}},
        completeness={
            "accounting": _claim(comp["accounting"]),
            "execution": _claim(comp["execution"]),
            "evidence": _claim(comp["evidence"]),
            w3creport.NO_VOID: _claim(comp["no_declared_check_is_void"]),
        },
    )


def reencode(raw: bytes) -> dict[str, Any]:
    if hashlib.sha256(raw).hexdigest() != POSTED_SHA256:
        raise Refused("the input is not the posted records.v0.1.json the R6 pins carry")
    posted = json.loads(raw)
    checks = _checks(posted["records"])
    report: dict[str, Any] = {
        "format": w3creport.FORMAT,
        "re-encoded-from": SOURCE,
        "domain": posted["run"]["domain"],
        "checks": checks,
        "evidence": [],
        "roll-up": _rollup(posted["rollup"], checks),
        "check-set": {
            "sha256": w3creport.check_set_root(checks, TREE_SHAPE),
            "leaf-count": len(checks),
            "tree-shape": TREE_SHAPE,
        },
    }
    for key, value in posted.items():
        if key not in CONSUMED:
            report.setdefault(key, value)
    return report


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("posted", type=Path)
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args(argv)
    try:
        report = reencode(args.posted.read_bytes())
    except Refused as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 1
    shape = w3creport.shape_errors(report)
    rows = [] if shape else w3creport.rejections(report)
    args.out.write_text(json.dumps(report, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
    if shape or rows:
        print(f"rejected: shape {shape} rows {rows}", file=sys.stderr)
        return 1
    print("conforms")
    return 0


if __name__ == "__main__":
    sys.exit(main())
