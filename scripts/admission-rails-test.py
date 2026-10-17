#!/usr/bin/env python3
"""The two admission rails agree, on the corpus and off it.

``corpora/admission.go`` (driven here through ``aee-verify`` and the corpus's
external contract) and ``packaging/agent_evidence_vectors/admission.py`` compute
the admission conjunction independently. This test holds them to one answer:

1. on every member of ``vectors-admission/``, both give the answer and the
   policy codes the manifest declares;
2. on every statement in the corpus crossed with a policy perturbed one knob at
   a time, both give the SAME answer and codes as each other, whatever it is. A
   corpus pins the cases somebody wrote down; the cross product is where two
   rails that agree on every written case still part.

    python3 scripts/admission-rails-test.py
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "vectors-admission"
sys.path.insert(0, str(ROOT / "packaging"))

from agent_evidence_vectors import admission  # noqa: E402


def build(dest: Path) -> str:
    binary = str(dest / "aee-verify")
    subprocess.run(["go", "build", "-o", binary, "./cmd/aee-verify"], cwd=ROOT, check=True)
    return binary


def go_answer(binary: str, statement: Path, policy: Path) -> dict[str, Any]:
    answer, why = admission.ask([binary, "-json"], str(statement), str(policy))
    if answer is None:
        raise SystemExit(f"FAIL: aee-verify gave no admission answer for {statement.name}: {why}")
    return answer


def py_answer(statement: Path, policy: Path) -> dict[str, Any]:
    out = admission.admit(statement.read_bytes(), admission.load_policy(policy.read_bytes()))
    return {"admitted": out["admitted"], "policyCodes": sorted(out["policyCodes"])}


def perturbations(base: dict[str, Any]) -> list[dict[str, Any]]:
    """The base policy, then each knob moved alone."""
    wrong = "0" * 64
    moves: list[dict[str, Any]] = [
        {},
        {"expectedCorpusDigest": wrong},
        {"expectedSubstrateDigest": wrong},
        {"expectedSubjectDigest": wrong},
        {
            "expectedCorpusDigest": None,
            "expectedSubstrateDigest": None,
            "expectedSubjectDigest": None,
        },
        {
            "expectedCorpusDigest": None,
            "expectedSubstrateDigest": None,
            "expectedSubjectDigest": None,
            "allowUnpinnedAnchors": True,
        },
        {"demandedClasses": None},
        {"demandedClasses": None, "allowUnpinnedScope": True},
        {"demandedClasses": ["XZ"]},
        {"substrateObservationKeys": None},
        {"acceptedResults": ["pass", "pass_indirect"]},
        {"acceptedResults": ["pass", "pass_indirect"], "admitUninterceptedCleanRows": True},
        {"acceptedResults": ["pass", "pass_indirect"], "admitUninterceptedCleanRows": False},
        {"admitUninterceptedCleanRows": True},
        {"acceptedResults": ["degraded"]},
        {"maxIssuanceLagSeconds": 1},
        {"maxIssuanceLagSeconds": 86400},
        {"allowPublishedTestKeys": None},
    ]
    out = []
    for move in moves:
        policy = dict(base)
        for key, value in move.items():
            if value is None:
                policy.pop(key, None)
            else:
                policy[key] = value
        out.append(policy)
    return out


def main() -> int:
    manifest = json.loads((CORPUS / "MANIFEST.json").read_text(encoding="utf-8"))
    failures: list[str] = []
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        binary = build(work)
        for v in manifest["vectors"]:
            want = {
                "admitted": v["expected"]["admitted"],
                "policyCodes": v["expected"]["policyCodes"],
            }
            statement, policy = CORPUS / v["file"], CORPUS / v["policy"]
            for rail, got in (
                ("go", go_answer(binary, statement, policy)),
                ("python", py_answer(statement, policy)),
            ):
                if got != want:
                    failures.append(f"{v['id']} ({rail}): {got}, the manifest declares {want}")
        print(
            f"corpus: {len(manifest['vectors'])} members, both rails checked against the manifest"
        )

        bases = {
            v["file"]: json.loads((CORPUS / v["policy"]).read_text(encoding="utf-8"))
            for v in manifest["vectors"]
            if v["expected"]["admitted"]
        }
        statements = sorted({v["file"] for v in manifest["vectors"]})
        compared = 0
        for rel in statements:
            base = bases.get(rel) or {}
            for i, policy in enumerate(perturbations(base)):
                path = work / f"policy-{Path(rel).stem}-{i}.json"
                path.write_text(json.dumps(policy), encoding="utf-8")
                go, py = go_answer(binary, CORPUS / rel, path), py_answer(CORPUS / rel, path)
                compared += 1
                if go != py:
                    failures.append(f"{rel} under {policy}: go {go}, python {py}")
        print(f"differential: {compared} statement-policy pairs, go against python")
    for f in failures:
        print(f"FAIL {f}")
    if not failures:
        print("PASS: the two admission rails agree")
    return 1 if failures else 0


if __name__ == "__main__":
    os.environ.pop("AEE_SUBSTRATE_KEYS", None)
    sys.exit(main())
