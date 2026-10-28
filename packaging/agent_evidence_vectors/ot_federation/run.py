"""Run the frozen ot-federation corpus, or write it out as a sealed fixture set.

``--output DIR`` judges every case and writes ``report.json``; the command exits 1
when any answer differs from the frozen one.

``--emit-fixtures DIR`` writes the corpus in the ot-federation-fixtures/v1 layout
(``manifest.json`` with per-file SHA-256, a package digest and each case's expected
verdict, and one file per case under ``cases/``), so any verifier that reads that
layout can be run against these cases unchanged.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import re
from pathlib import Path
from typing import Any

from ..record_paths import portable_command, write_records
from .reader import CLAIMS, MalformedCase, evaluate, load_case

DISTRIBUTION = "agent-evidence-vectors"
PACKAGED_CORPUS = Path(__file__).parent / "corpus"
NON_CLAIMS = (
    "decision_authenticity",
    "capture_completeness",
    "observer_independence_from_the_deployment",
    "physical_plant_state",
)


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


def load_corpus(root: Path) -> tuple[dict[str, Any], dict[str, str]]:
    """Check every corpus member against the manifest before anything is judged."""
    manifest = load_case((root / "manifest.json").read_bytes())
    digests: dict[str, str] = {}
    for name, pinned in manifest["members"].items():
        actual = "sha256:" + hashlib.sha256((root / name).read_bytes()).hexdigest()
        if actual != pinned:
            raise MalformedCase(f"corpus member {name} is {actual}, manifest pins {pinned}")
        digests[name] = actual
    return load_case((root / "cases.json").read_bytes()), digests


def run_corpus(root: Path) -> dict[str, Any]:
    """Judge every case, then compare with its expected answer."""
    cases, digests = load_corpus(root)
    results, failures = [], []
    for case in cases["cases"]:
        got = evaluate(case["case"])
        actual = {"verdict": got["verdict"], "claims": got["claims"]}
        if actual != case["expected"]:
            failures.append(case["id"])
        results.append(
            {
                "case_id": case["id"],
                "fault_shape": case["fault_shape"],
                "actual": actual,
                "expected": case["expected"],
                "reason": got["reason"],
            }
        )
    return {
        "schema": "aev-ot-federation-report/v1",
        "input_digests": digests,
        "claims": list(CLAIMS),
        "non_claims": list(NON_CLAIMS),
        "results": results,
        "failures": failures,
    }


def emit_fixtures(root: Path, out: Path) -> dict[str, Any]:
    """Write the corpus as an ot-federation-fixtures/v1 set and return its manifest."""
    cases, _ = load_corpus(root)
    if out.exists():
        raise FileExistsError(out)
    (out / "cases").mkdir(parents=True)
    files, entries = [], []
    for case in cases["cases"]:
        path = f"cases/{case['id']}.json"
        body = (json.dumps(case["case"], ensure_ascii=False, indent=1) + "\n").encode("utf-8")
        (out / path).write_bytes(body)
        files.append({"path": path, "sha256": hashlib.sha256(body).hexdigest()})
        expected = case["expected"]
        first = next(
            (
                c
                for w in ("CONTRADICTED", "NOT_ESTABLISHED")
                for c in CLAIMS
                if expected["claims"] and expected["claims"][c] == w
            ),
            None,
        )
        entry = {
            "case_id": case["id"],
            "kind": "positive" if expected["verdict"] == "ESTABLISHED" else "negative",
            "expected_verdict": expected["verdict"],
            "fault": case["fault_shape"],
        }
        if first is not None:
            entry["claim_id"] = first
        entries.append(entry)
    lines = "".join(f"{f['path']} {f['sha256']}\n" for f in sorted(files, key=lambda f: f["path"]))
    manifest = {
        "schema": "ot-federation-fixtures/v1",
        "fixture_set": "aev-ot-federation",
        "scope": (
            "Synthetic trails written for verifier adequacy; not recorded from any deployment."
        ),
        "digest_rules": {
            "evidence_sha256": "SHA-256 over the UTF-8 bytes of json.dumps(remora_evidence, "
            "sort_keys=True, separators=(',', ':'), ensure_ascii=False)"
        },
        "package_digest_rule": "sha256 over the UTF-8 text formed by one line per files entry, "
        "'<path> <sha256>\\n', sorted by path.",
        "package_digest": "sha256:" + hashlib.sha256(lines.encode("utf-8")).hexdigest(),
        "files": files,
        "cases": entries,
    }
    (out / "manifest.json").write_text(json.dumps(manifest, indent=1) + "\n", encoding="utf-8")
    return manifest


def main(argv: list[str] | None = None) -> int:
    """Judge the corpus into a new directory, or emit it as a fixture set."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, default=PACKAGED_CORPUS)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--output", type=Path)
    mode.add_argument("--emit-fixtures", type=Path)
    parser.add_argument("--implementation-revision", default=None)
    args = parser.parse_args(argv)
    if args.implementation_revision is not None and not re.fullmatch(
        r"[0-9a-f]{40}", args.implementation_revision
    ):
        parser.error("implementation revision must be a 40-character Git commit")
    if args.emit_fixtures is not None:
        manifest = emit_fixtures(args.corpus, args.emit_fixtures)
        print(
            json.dumps(
                {"cases": len(manifest["cases"]), "package_digest": manifest["package_digest"]}
            )
        )
        return 0
    if args.output.exists():
        raise FileExistsError(args.output)
    report = run_corpus(args.corpus)
    report["implementation_revision"] = _revision(args.implementation_revision)
    report["environment"] = f"Python {platform.python_version()} on {platform.platform()}"
    report["command"] = portable_command()
    write_records(args.output, {"report.json": report})
    print(json.dumps({"cases": len(report["results"]), "failures": report["failures"]}))
    return int(bool(report["failures"]))


if __name__ == "__main__":
    raise SystemExit(main())
