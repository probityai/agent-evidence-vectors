#!/usr/bin/env python3
"""One-variable claim-downgrade experiment on v0.1 evidence links.

Question: when exactly one evidence link behind a claim in a v0.1 report is
removed, broken or made unreadable, does a reader's output change, and does it
change the way the v0.1 text says it should?

Three base reports, each accepted with its claim intact:

  B1  record-level claims: a fail record with other-verdict demonstrated and
      discrimination demonstrated, both citing one evidence object whose two
      observations are referenced by digest (v0.1 sections 1.3, 2, 3).
  B2  run-level claim: an all-pass run whose negative-capable field names a
      control that failed under the run's checker and constraint set (5.4).
  B3  run-level claim: an all-pass run whose negative-capable field names a
      prior discriminating run by a set reference (5.4, 3, 3.1).

Each case changes one variable of one base. For each case the script records
the outcome the v0.1 text gives (with its section), what the Python reader
returns with the resolution store supplied and without it, and what the Rust
reader prints in its --report mode (which resolves nothing). A harness column
derives the claim status the reading table implies (verified, unchecked,
unbound, refused); that column is computed here, not printed by any reader.

Both readers are from agent-evidence-vectors and have one author, who also
wrote this script and ran it. The run shows what those two readers do; it says
nothing about a reader someone else wrote. The command is in run.sh.

Usage:
  python3 -I claim_downgrade.py --out results.json [--rust PATH]
The Python reader is imported as agent_evidence_vectors.w3creport from the
installed package; the script records its version and the module's sha256.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import os
import platform
import subprocess
import sys
import tempfile
from collections.abc import Callable
from typing import Any

from agent_evidence_vectors import w3creport as W

FORMAT = "public-agent-conformance/report/v0.1"
OBS_PASS = {"rules": [], "verdict": "pass"}
OBS_FAIL = {"rules": ["R-1"], "verdict": "fail"}


def digest(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def store() -> dict[str, Any]:
    out = {}
    for name, body in (("obs-pass", OBS_PASS), ("obs-fail", OBS_FAIL)):
        out[name] = dict(body, sha256=digest(body))
    return out


def seal(report: dict[str, Any]) -> dict[str, Any]:
    """Recompute the roll-up counts and the check-set binding the way an emitter would."""
    checks = report["checks"]
    rollup = report["roll-up"]
    counts = {"declared": len(checks), "exercised": 0}
    for s in W.STATES:
        counts[s] = 0
    for c in checks:
        counts[c["state"]] += 1
        if c["state"] != "not-exercised":
            counts["exercised"] += 1
    rollup.update(counts)
    carried = referenced = 0
    for item in report.get("evidence", []):
        for o in item["observations"]:
            if "carried" in o:
                carried += 1
            else:
                referenced += 1
    rollup["carried"], rollup["referenced"] = carried, referenced
    report["check-set"] = {
        "leaf-count": len(checks),
        "sha256": W.check_set_root(checks, "flat"),
        "tree-shape": "flat",
    }
    return report


def base_b1() -> dict[str, Any]:
    s = store()
    return seal(
        {
            "format": FORMAT,
            "domain": {"id": "d-run", "description": "the run's declared domain"},
            "checks": [
                {"check": "c-pass", "state": "pass"},
                {
                    "check": "c-fail",
                    "state": "fail",
                    "other-verdict": {"value": "demonstrated", "ref": "e-1"},
                    "discrimination": {"value": "demonstrated", "ref": "e-1"},
                },
            ],
            "evidence": [
                {
                    "id": "e-1",
                    "changed": "input artifact",
                    "fixed": {"checker": "checker-1", "constraint-set": "cs-1", "domain": "d-run"},
                    "compared": ["verdict", "fired-rule list"],
                    "moved": ["verdict", "fired-rule list"],
                    "delta": {"changes": [{"field": "artifact/field", "before": 1, "after": 2}]},
                    "observations": [
                        {"reference": {"vector": "obs-pass", "sha256": s["obs-pass"]["sha256"]}},
                        {"reference": {"vector": "obs-fail", "sha256": s["obs-fail"]["sha256"]}},
                    ],
                }
            ],
            "roll-up": {"negative-capable": {"kind": "shown-by-run"}},
        }
    )


def base_b2() -> dict[str, Any]:
    return seal(
        {
            "format": FORMAT,
            "domain": {"id": "d-run", "description": "the run's declared domain"},
            "fixed": {"checker": "checker-1", "constraint-set": "cs-1"},
            "checks": [
                {"check": "c-pass", "state": "pass"},
                {"check": "c-pass-2", "state": "pass"},
            ],
            "roll-up": {
                "negative-capable": {
                    "kind": "control-failed",
                    "control": {
                        "checks": ["c-pass", "c-pass-2"],
                        "fixed": {"checker": "checker-1", "constraint-set": "cs-1"},
                        "state": "fail",
                    },
                }
            },
        }
    )


def base_b3() -> dict[str, Any]:
    return seal(
        {
            "format": FORMAT,
            "domain": {"id": "d-run", "description": "the run's declared domain"},
            "checks": [
                {"check": "c-pass", "state": "pass"},
                {"check": "c-pass-2", "state": "pass"},
            ],
            "roll-up": {
                "negative-capable": {
                    "kind": "prior-discriminating-run",
                    "check-identity": ["c-pass", "c-pass-2"],
                    "reference": {
                        "sha256": digest({"prior": "run", "fail": 1}),
                        "leaf-count": 2,
                        "tree-shape": "flat",
                    },
                }
            },
        }
    )


Mut = Callable[[dict[str, Any], dict[str, Any]], None]


def nothing(r: dict[str, Any], s: dict[str, Any]) -> None:
    return None


def withhold_store(r: dict[str, Any], s: dict[str, Any]) -> None:
    s.clear()


def obs_digest_mismatch(r: dict[str, Any], s: dict[str, Any]) -> None:
    r["evidence"][0]["observations"][1]["reference"]["sha256"] = "0" * 64


def obs_unresolvable(r: dict[str, Any], s: dict[str, Any]) -> None:
    del s["obs-fail"]


def disc_ref_dangling(r: dict[str, Any], s: dict[str, Any]) -> None:
    r["checks"][1]["discrimination"]["ref"] = "e-missing"


def disc_ref_removed(r: dict[str, Any], s: dict[str, Any]) -> None:
    del r["checks"][1]["discrimination"]["ref"]


def obs_digest_removed(r: dict[str, Any], s: dict[str, Any]) -> None:
    del r["evidence"][0]["observations"][1]["reference"]["sha256"]


def evidence_checker_unpinned(r: dict[str, Any], s: dict[str, Any]) -> None:
    del r["evidence"][0]["fixed"]["checker"]


def evidence_changed_checker(r: dict[str, Any], s: dict[str, Any]) -> None:
    r["evidence"][0]["changed"] = "checker rule"


def resolved_content_differs(r: dict[str, Any], s: dict[str, Any]) -> None:
    # The resolved body still carries the digest the report cites, but its
    # verdict no longer differs from the other side: a resolver that returns a
    # stale body under the cited digest.
    s["obs-fail"]["verdict"] = "pass"


def control_checker_differs(r: dict[str, Any], s: dict[str, Any]) -> None:
    r["roll-up"]["negative-capable"]["control"]["fixed"]["checker"] = "checker-2"


def control_config_differs(r: dict[str, Any], s: dict[str, Any]) -> None:
    r["roll-up"]["negative-capable"]["control"]["fixed"]["constraint-set"] = "cs-2"


def control_binding_removed(r: dict[str, Any], s: dict[str, Any]) -> None:
    del r["roll-up"]["negative-capable"]["control"]["fixed"]


def run_binding_removed(r: dict[str, Any], s: dict[str, Any]) -> None:
    del r["fixed"]


def control_inconclusive(r: dict[str, Any], s: dict[str, Any]) -> None:
    r["roll-up"]["negative-capable"]["control"]["state"] = "inconclusive"


def control_names_other_check(r: dict[str, Any], s: dict[str, Any]) -> None:
    r["roll-up"]["negative-capable"]["control"]["checks"] = ["c-elsewhere"]


def control_operator_changed(r: dict[str, Any], s: dict[str, Any]) -> None:
    r["roll-up"]["negative-capable"]["control"]["runner"] = "a different operator"


def prior_leafcount_removed(r: dict[str, Any], s: dict[str, Any]) -> None:
    del r["roll-up"]["negative-capable"]["reference"]["leaf-count"]


def prior_digest_mismatch(r: dict[str, Any], s: dict[str, Any]) -> None:
    r["roll-up"]["negative-capable"]["reference"]["sha256"] = "0" * 64


def prior_identity_other(r: dict[str, Any], s: dict[str, Any]) -> None:
    r["roll-up"]["negative-capable"]["check-identity"] = ["c-elsewhere"]


# (case, base, variable changed, mutation, text outcome, text section)
# text outcome is one of: accept-verified, accept-unchecked, accept-unbound, reject
CASES: list[tuple[str, str, str, Mut, str, str]] = [
    ("B1-0", "B1", "none", nothing, "accept-verified", "3 line 1"),
    (
        "B1-1",
        "B1",
        "reader holds no resolution store",
        withhold_store,
        "accept-unchecked",
        "3 line 3",
    ),
    (
        "B1-2",
        "B1",
        "one observation digest differs from the resolved bytes",
        obs_digest_mismatch,
        "reject",
        "3 line 2",
    ),
    (
        "B1-3",
        "B1",
        "one observation does not resolve",
        obs_unresolvable,
        "accept-unchecked",
        "3 line 3",
    ),
    (
        "B1-4",
        "B1",
        "discrimination cites an evidence id the report lacks",
        disc_ref_dangling,
        "reject",
        "4 row 11",
    ),
    ("B1-5", "B1", "discrimination cites no evidence", disc_ref_removed, "reject", "4 row 11"),
    (
        "B1-6",
        "B1",
        "one referenced observation carries no digest",
        obs_digest_removed,
        "reject",
        "4 row 14",
    ),
    (
        "B1-7",
        "B1",
        "evidence leaves the checker identity unpinned",
        evidence_checker_unpinned,
        "reject",
        "1.3, 2 fixed",
    ),
    (
        "B1-8",
        "B1",
        "evidence changed slot is the checker",
        evidence_changed_checker,
        "reject",
        "4 row 12",
    ),
    (
        "B1-9",
        "B1",
        "resolved body under the cited digest no longer differs in verdict",
        resolved_content_differs,
        "reject",
        "4 row 13",
    ),
    ("B2-0", "B2", "none", nothing, "accept-verified", "5.4"),
    (
        "B2-1",
        "B2",
        "control checker differs from the run's",
        control_checker_differs,
        "reject",
        "5.4 condition 2",
    ),
    (
        "B2-2",
        "B2",
        "control constraint set differs from the run's",
        control_config_differs,
        "reject",
        "5.4 condition 2",
    ),
    (
        "B2-3",
        "B2",
        "control declares no checker or constraint set",
        control_binding_removed,
        "accept-unbound",
        "5.4 condition 2; 5.5 O7",
    ),
    (
        "B2-4",
        "B2",
        "run declares no checker or constraint set",
        run_binding_removed,
        "accept-unbound",
        "5.4 condition 2; 5.5 O7",
    ),
    (
        "B2-5",
        "B2",
        "control state inconclusive",
        control_inconclusive,
        "reject",
        "5.4 fail means fail",
    ),
    (
        "B2-6",
        "B2",
        "control names a check the run does not declare",
        control_names_other_check,
        "reject",
        "5.4 condition 1",
    ),
    (
        "B2-7",
        "B2",
        "control carries a different operator",
        control_operator_changed,
        "accept-verified",
        "none: v0.1 binds no operator",
    ),
    ("B3-0", "B3", "none", nothing, "accept-unchecked", "5.4 prior run; 3 line 3"),
    (
        "B3-1",
        "B3",
        "prior-run reference carries no leaf count",
        prior_leafcount_removed,
        "reject",
        "3.1",
    ),
    (
        "B3-2",
        "B3",
        "prior-run reference digest matches nothing obtainable",
        prior_digest_mismatch,
        "accept-unchecked",
        "5.4 prior run; 3 line 3",
    ),
    (
        "B3-3",
        "B3",
        "prior run names checks the run does not declare",
        prior_identity_other,
        "reject",
        "5.4 identity survives",
    ),
]

BASES = {"B1": base_b1, "B2": base_b2, "B3": base_b3}


def claim_status(base: str, report: dict[str, Any], s: dict[str, Any], rejected: bool) -> str:
    """The claim status the reading table implies; computed here, printed by no reader."""
    if rejected:
        return "refused"
    if base == "B1":
        for o in report["evidence"][0]["observations"]:
            ref = o["reference"]
            body = s.get(ref.get("vector"))
            if body is None or body.get("sha256") != ref.get("sha256"):
                return "unchecked"
        return "verified"
    if base == "B2":
        field = report["roll-up"]["negative-capable"]["control"]
        if "fixed" not in field or "fixed" not in report:
            return "unbound"
        return "verified"
    return "unchecked"  # B3: no reader here resolves a prior-run reference


def file_sha256(path: str) -> str:
    """The binary's content digest; its path is the runner's own and is not recorded."""
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


def rust_rows(binary: str, report: dict[str, Any]) -> str:
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "report.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2, sort_keys=True)
            fh.write("\n")
        proc = subprocess.run(
            [binary, "--report", path], capture_output=True, text=True, check=False
        )
    for line in proc.stdout.splitlines():
        if " rows:" in line or line.startswith("FAIL rows") or line.startswith("ok   rows"):
            return line.strip()
    out, err = proc.stdout.strip()[-200:], proc.stderr.strip()[-200:]
    return f"no rows line (exit {proc.returncode}): {out} {err}"


def py_judge(report: dict[str, Any], s: dict[str, Any] | None) -> dict[str, Any]:
    shape = W.shape_errors(report)
    if shape:
        return {"shape": shape, "rows": None}
    return {"shape": [], "rows": W.rejections(report, resolves=s)}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--rust", default=None)
    args = ap.parse_args()
    module_path = W.__file__
    with open(module_path, "rb") as fh:
        module_sha = hashlib.sha256(fh.read()).hexdigest()
    rows = []
    for case, base, variable, mut, text_outcome, section in CASES:
        report = BASES[base]()
        s = store()
        mut(report, s)
        # An honest emitter re-seals after writing the record: the roll-up counts
        # and the check-set binding are recomputed, so the one variable a case
        # changes is the evidence link and not, as well, the binding over it.
        seal(report)
        with_store = py_judge(report, s)
        without_store = py_judge(report, None)
        rejected = bool(with_store["shape"]) or bool(with_store["rows"])
        status = claim_status(base, report, s, rejected)
        if text_outcome.startswith("accept"):
            text_status = text_outcome.split("-", 1)[1]
        else:
            text_status = "refused"
        row = {
            "case": case,
            "base": base,
            "variable": variable,
            "text_outcome": text_outcome,
            "text_section": section,
            "py_with_store": with_store,
            "py_without_store": without_store,
            "claim_status_harness": status,
            "agrees_with_text": status == text_status,
            "report_sha256": digest(report),
        }
        if args.rust:
            row["rust_report_mode"] = rust_rows(args.rust, report)
        rows.append(row)
    base_outputs = {}
    for r in rows:
        if r["case"].endswith("-0"):
            base_outputs[r["base"]] = (
                json.dumps(r["py_with_store"], sort_keys=True),
                json.dumps(r["py_without_store"], sort_keys=True),
                r.get("rust_report_mode"),
            )
    for r in rows:
        b = base_outputs[r["base"]]
        mine = (
            json.dumps(r["py_with_store"], sort_keys=True),
            json.dumps(r["py_without_store"], sort_keys=True),
            r.get("rust_report_mode"),
        )
        r["reader_output_identical_to_base"] = {
            "py_with_store": mine[0] == b[0],
            "py_without_store": mine[1] == b[1],
            "rust_report_mode": mine[2] == b[2],
        }
        r["silent_downgrade"] = (
            r["claim_status_harness"] != "verified"
            and r["claim_status_harness"] != "refused"
            and r["reader_output_identical_to_base"]["py_with_store"]
            and not r["case"].endswith("-0")
        )
    result = {
        "experiment": "one-variable claim-downgrade on v0.1 evidence links",
        "run_by": "the author of both readers and of this script",
        "reader_py": {
            "package": "agent-evidence-vectors",
            "version": importlib.metadata.version("agent-evidence-vectors"),
            "module": "agent_evidence_vectors.w3creport",
            "module_sha256": module_sha,
        },
        "reader_rs": {
            "binary": os.path.basename(args.rust),
            "binary_sha256": file_sha256(args.rust),
            "mode": "--report (resolves nothing)",
        }
        if args.rust
        else None,
        "interpreter": " ".join(
            (
                platform.python_implementation(),
                platform.python_version(),
                platform.system(),
                platform.machine(),
            )
        ),
        "cases": rows,
        "summary": {
            "cases": len(rows),
            "agrees_with_text": sum(r["agrees_with_text"] for r in rows),
            "silent_downgrade": [r["case"] for r in rows if r["silent_downgrade"]],
            "disagrees_with_text": [r["case"] for r in rows if not r["agrees_with_text"]],
            "refused_with_store_accepted_without": [
                r["case"]
                for r in rows
                if (r["py_with_store"]["rows"] or r["py_with_store"]["shape"])
                and r["py_without_store"]["rows"] == []
                and not r["py_without_store"]["shape"]
            ],
        },
    }
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2, sort_keys=True)
        fh.write("\n")
    print(json.dumps(result["summary"], indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
