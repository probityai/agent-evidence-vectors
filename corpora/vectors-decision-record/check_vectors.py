"""Judge every decision-record member with agent-evidence-verify and check the corpus digest.

1. The corpus digest recomputes.
2. Every member reads, under the profile it names, to the verdict and code MANIFEST.json declares,
   and every dimension status the entry declares is the one the report gives.
3. Every baseline member that names a published case declares that case's expected values.

The judge is ``agent_evidence_verify.decision_record``. Without it the check exits 2 and says it did
not run: absence is never a pass.

    uv run --with agent-evidence-verify python corpora/vectors-decision-record/check_vectors.py
"""

from __future__ import annotations

import importlib
import json
import sys
from pathlib import Path

from digest import corpus_digest

HERE = Path(__file__).resolve().parent
BINDING = ("specification_digests", "specification_statements", "record_statements", "action_binding",
           "stage_order", "authorisation_recheck", "observed_results", "rationale_provenance")


def declared_differences(report: dict, declared: dict) -> list[str]:
    out = []
    for name, want in declared.items():
        if name == "strict":
            out += [f"strict.{k}: declared {v}, read {report['strict'][k]['status']}"
                    for k, v in want.items() if report["strict"][k]["status"] != v]
        elif report[name]["status"] != want:
            out.append(f"{name}: declared {want}, read {report[name]['status']}")
    return out


def main() -> int:
    try:
        # Loaded by name: the package is installed only where this check runs
        # (CI pins it), so the type gate must not resolve it from the repo env.
        decision_record = importlib.import_module("agent_evidence_verify.decision_record")
    except ImportError:
        print("decision-record: NOT RUN: agent-evidence-verify is not installed")
        return 2
    manifest = json.loads((HERE / "MANIFEST.json").read_text(encoding="utf-8"))
    cases = {c["id"]: c for c in json.loads((HERE / "source" / "cases.json").read_bytes())["binding_cases"]}
    failures = []
    for entry in manifest["vectors"]:
        member = json.loads((HERE / entry["path"]).read_bytes())
        report, verdict, code = decision_record.read_member(member)
        want = entry["expected"]
        if (verdict, code) != (want["verdict"], want["code"]):
            failures.append(f"{entry['id']}: read {verdict} {code}, declared {want['verdict']} {want['code']}")
        failures += [f"{entry['id']}: {d}" for d in declared_differences(report, want["dimensions"])]
        if "sourceCase" in entry:
            published = cases[entry["sourceCase"]]["expected"]
            derived = {name: published.get(name, "verified") for name in BINDING}
            if derived != want["dimensions"]:
                failures.append(f"{entry['id']}: declared dimensions are not case {entry['sourceCase']}'s")
            failures += [f"{entry['id']}: {d}" for d in decision_record.expected_differences(
                cases[entry["sourceCase"]], report)]
    if corpus_digest(manifest, str(HERE)) != manifest["corpusDigest"]:
        failures.append("corpusDigest does not recompute")
    for line in failures:
        print(f"FAIL {line}")
    print(f"decision-record: {len(manifest['vectors'])} members, {len(failures)} failures")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
