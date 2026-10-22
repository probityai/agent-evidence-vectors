"""Judge the ACS outage posture vectors and retain one report per run.

    agent-evidence-vectors-acs-outage --output DIR
    agent-evidence-vectors-acs-outage --output DIR --verifier "my-verifier"
    agent-evidence-vectors-acs-outage CASE_DIR/case.json --json

With no ``--verifier`` the package's reference reader answers every case. With
one, every case is handed to that command as ``<verifier> <case.json> --json``
and its answer is compared with the expected one; a verifier that cannot run,
answers nothing or exits with a code that disagrees with its decision fails the
case. Exit 0 only when every case was answered and matched.
"""

from __future__ import annotations

import argparse
import json
import platform
import re
import shlex
import subprocess
import sys
from pathlib import Path
from typing import Any

from .reader import EXIT_FOR, SUITE, SUPPORTED, sha256_hex, verify

DISTRIBUTION = "agent-evidence-vectors"
PACKAGED_CORPUS = Path(__file__).parent / "corpus"
NON_CLAIMS = (
    "a real coding agent behaves as the synthetic host does",
    "the outage behaviour holds beyond a clean refused connection",
    "the deployment is conformant",
)


class CorpusError(ValueError):
    """The corpus on disk is not the one its manifest pins."""


def _check_case(root: Path, case: dict[str, Any], by_id: dict[str, Any]) -> None:
    directory = root / "cases" / case["id"]
    if {p.name for p in directory.iterdir() if p.is_file()} != set(case["files"]):
        raise CorpusError(f"{case['id']}: file set changed")
    for name, digest in case["files"].items():
        if sha256_hex((directory / name).read_bytes()) != digest:
            raise CorpusError(f"{case['id']}: {name} digest mismatch")
    if case["expected"]["decision"] != SUPPORTED:
        twin = by_id.get(case.get("twin", ""))
        if twin is None or twin["expected"]["decision"] != SUPPORTED:
            raise CorpusError(f"{case['id']}: a refused case must name a supported twin")


def load_manifest(root: Path) -> dict[str, Any]:
    """Check every pinned file and the case set before any case is judged."""
    manifest = json.loads((root / "MANIFEST.json").read_text(encoding="utf-8"))
    if manifest.get("suite") != SUITE:
        raise CorpusError("unexpected suite")
    cases = manifest["cases"]
    if sha256_hex(json.dumps(cases, sort_keys=True).encode()) != manifest["corpusDigest"]:
        raise CorpusError("manifest digest mismatch")
    ids = [c["id"] for c in cases]
    if not ids or len(set(ids)) != len(ids):
        raise CorpusError("empty or duplicate case identifiers")
    if {p.name for p in (root / "cases").iterdir() if p.is_dir()} != set(ids):
        raise CorpusError("case directories do not match the manifest")
    for name, digest in manifest["sources"].items():
        if sha256_hex((root / "source" / name).read_bytes()) != digest:
            raise CorpusError(f"source {name} digest mismatch")
    by_id = {c["id"]: c for c in cases}
    for case in cases:
        _check_case(root, case, by_id)
    return manifest


def _external(command: list[str], case_json: Path) -> tuple[bool, dict[str, Any] | str]:
    try:
        result = subprocess.run([*command, str(case_json), "--json"], capture_output=True,
                                text=True, timeout=90, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, f"verifier did not run: {exc}"
    try:
        answer = json.loads(result.stdout.strip().splitlines()[-1])
        observed = {key: answer[key] for key in ("decision", "reason")}
    except (ValueError, KeyError, TypeError, IndexError):
        return True, f"verifier returned no decision (exit {result.returncode})"
    if EXIT_FOR.get(str(observed["decision"])) != result.returncode:
        return True, f"exit {result.returncode} disagrees with decision {observed['decision']}"
    return True, observed


def run_corpus(root: Path, verifier: list[str] | None = None,
               skip: frozenset[str] = frozenset()) -> dict[str, Any]:
    """Judge every case and compare with its expected answer."""
    manifest = load_manifest(root)
    results, failures, answered = [], [], 0
    for case in manifest["cases"]:
        case_json = root / "cases" / case["id"] / "case.json"
        if verifier is None:
            ran, observed = True, verify(case_json, skip)
        else:
            ran, observed = _external(verifier, case_json)
        answered += int(ran)
        if observed != case["expected"]:
            failures.append(case["id"])
        results.append({"case_id": case["id"], "control": case["control"],
                        "expected": case["expected"], "observed": observed})
    return {
        "schema": "aev-acs-outage-report/v1",
        "suite": SUITE,
        "corpusDigest": manifest["corpusDigest"],
        "rail": "reference-reader" if verifier is None else "external",
        "verifier": verifier,
        "answered": answered,
        "total": len(manifest["cases"]),
        "non_claims": list(NON_CLAIMS),
        "results": results,
        "failures": failures,
    }


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


def main(argv: list[str] | None = None) -> int:
    """Judge one case, or the whole corpus into a new output directory."""
    parser = argparse.ArgumentParser(description=(__doc__ or SUITE).splitlines()[0])
    parser.add_argument("case", nargs="?", type=Path, help="judge one case.json")
    parser.add_argument("--json", action="store_true", help="print one decision as JSON")
    parser.add_argument("--corpus", type=Path, default=PACKAGED_CORPUS)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--verifier", help="command line of the verifier under test")
    parser.add_argument("--implementation-revision", default=None)
    args = parser.parse_args(argv)
    if args.implementation_revision is not None and not re.fullmatch(
        r"[0-9a-f]{40}", args.implementation_revision
    ):
        parser.error("implementation revision must be a 40-character Git commit")
    if args.case is not None:
        answer = verify(args.case)
        print(json.dumps(answer, sort_keys=True) if args.json
              else f"{answer['decision']} {answer['reason']}")
        return EXIT_FOR[answer["decision"]]
    if args.output is None:
        parser.error("--output is required when judging the corpus")
    try:
        report = run_corpus(args.corpus,
                            shlex.split(args.verifier) if args.verifier else None)
    except (CorpusError, OSError, ValueError, KeyError) as exc:
        print(f"invalid corpus: {exc}", file=sys.stderr)
        return 2
    report["implementation_revision"] = _revision(args.implementation_revision)
    report["environment"] = f"Python {platform.python_version()} on {platform.platform()}"
    args.output.mkdir(parents=True, exist_ok=False)
    (args.output / "report.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n",
                                             encoding="utf-8")
    for failure in report["failures"]:
        print(f"FAIL {failure}")
    print(f"{SUITE}: answered {report['answered']} of {report['total']} cases, "
          f"{len(report['failures'])} disagreements")
    if not report["answered"]:
        return 2
    return int(bool(report["failures"]) or report["answered"] != report["total"])


if __name__ == "__main__":
    raise SystemExit(main())
