"""Evaluation claim records: verify one, emit one, or replay the frozen corpus.

    agent-evidence-vectors claim verify --record R.json --rule RULE.json [--case-set CS.json ...]
    agent-evidence-vectors claim emit --case-set CS.json --results RESULTS.json ...
    agent-evidence-vectors claim run --output DIR

``verify`` exits 0 when the record is admitted and its verdict is pass, 3 when it
is admitted with a verdict of fail or incomplete, 1 when it is refused and 2 on
unusable input. The acceptance rule is the relying party's file, never the
producer's: it pins the profile and the case sets the record is judged under.
"""

from __future__ import annotations

import argparse
import json
import platform
import re
import sys
from pathlib import Path
from typing import Any

from ..record_paths import portable_command, write_records
from .ops import apply_ops
from .reader import (
    CLAIM_TYPE,
    CODES,
    STATEMENT_TYPE,
    MalformedInput,
    check_case_set,
    check_profile,
    digest_of,
    emit,
    index_by_digest,
    parse_strict,
    sha256_tag,
    summary,
    verify,
)

DISTRIBUTION = "agent-evidence-vectors"
PACKAGED_CORPUS = Path(__file__).parent / "corpus"
EXIT_PASS, EXIT_REFUSED, EXIT_UNUSABLE, EXIT_NOT_PASS = 0, 1, 2, 3


def _read(path: Path) -> Any:
    return parse_strict(path.read_bytes())


def packaged_profiles(root: Path = PACKAGED_CORPUS) -> dict[str, Any]:
    """The published profiles by digest; a rule pins one, or the caller supplies another."""
    return index_by_digest(
        check_profile(_read(p)) for p in sorted((root / "profiles").glob("*.json"))
    )


def load_corpus(root: Path) -> dict[str, Any]:
    """Check every member against the manifest, then load profiles, case sets, rules and cases."""
    manifest = _read(root / "manifest.json")
    on_disk = sorted(
        str(p.relative_to(root))
        for p in root.rglob("*")
        if p.is_file() and p.name != "manifest.json"
    )
    if sorted(manifest["members"]) != on_disk:
        raise MalformedInput("corpus members differ from the manifest's list")
    for name, pinned in manifest["members"].items():
        actual = sha256_tag((root / name).read_bytes())
        if actual != pinned:
            raise MalformedInput(f"corpus member {name} is {actual}, manifest pins {pinned}")
    return {
        "profiles": packaged_profiles(root),
        "case_sets": index_by_digest(
            check_case_set(_read(p)) for p in sorted((root / "case-sets").glob("*.json"))
        ),
        "rules": {p.stem: _read(p) for p in sorted((root / "rules").glob("*.json"))},
        "cases": _read(root / "cases.json"),
        "digests": dict(manifest["members"]),
    }


def run_corpus(root: Path) -> dict[str, Any]:
    """Judge every case without reading its expected answer, then compare."""
    corpus = load_corpus(root)
    results, failures = [], []
    for case in corpus["cases"]["cases"]:
        rule = corpus["rules"][case["rule"]]
        actual = verify(case["record"], rule, corpus["profiles"], corpus["case_sets"])
        got = summary(actual)
        entry: dict[str, Any] = {
            "case_id": case["id"],
            "kind": case["kind"],
            "about": case["about"],
            "actual": actual,
            "expected": case["expected"],
        }
        ok = got == case["expected"]
        if case["kind"] == "negative":
            repaired = summary(
                verify(
                    apply_ops(case["record"], case["repair"]),
                    corpus["rules"][case.get("repair_rule", case["rule"])],
                    corpus["profiles"],
                    corpus["case_sets"],
                )
            )
            entry["repaired"] = repaired
            ok = ok and repaired["result"] == "ADMITTED"
        if not ok:
            failures.append(case["id"])
        results.append(entry)
    return {
        "schema": "aev-claim-record-report/v1",
        "claim_type": CLAIM_TYPE,
        "codes": list(CODES),
        "input_digests": corpus["digests"],
        "results": results,
        "failures": failures,
    }


def _cmd_run(args: argparse.Namespace) -> int:
    if args.implementation_revision is not None and not re.fullmatch(
        r"[0-9a-f]{40}", args.implementation_revision
    ):
        raise SystemExit("implementation revision must be a 40-character Git commit")
    if args.output.exists():
        raise FileExistsError(args.output)
    report = run_corpus(args.corpus)
    report["implementation_revision"] = _revision(args.implementation_revision)
    report["environment"] = f"Python {platform.python_version()} on {platform.platform()}"
    report["command"] = portable_command()
    write_records(args.output, {"report.json": report})
    print(json.dumps({"cases": len(report["results"]), "failures": report["failures"]}))
    return int(bool(report["failures"]))


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


def _cmd_verify(args: argparse.Namespace) -> int:
    profiles = packaged_profiles()
    profiles.update(index_by_digest(check_profile(_read(p)) for p in args.profile))
    case_sets = index_by_digest(check_case_set(_read(p)) for p in args.case_set)
    outcome = verify(_read(args.record), _read(args.rule), profiles, case_sets)
    print(json.dumps(outcome, indent=2, sort_keys=True))
    if outcome["result"] != "ADMITTED":
        return EXIT_REFUSED
    return EXIT_PASS if outcome["verdict"] == "pass" else EXIT_NOT_PASS


def _ref(name: str, digest: str) -> dict[str, str]:
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
        raise SystemExit(f"{name} digest must be sha256:<64 lowercase hex>")
    return {"name": name, "digest": digest}


def _cmd_emit(args: argparse.Namespace) -> int:
    profile = check_profile(_read(args.profile))
    record = emit(
        case_set=_read(args.case_set),
        results=_read(args.results),
        profile={"id": profile["id"], "digest": digest_of(profile)},
        implementation=_ref(args.implementation_name, args.implementation_digest),
        verifier=_ref(args.verifier_name, args.verifier_digest),
        observation_vantage=args.observation_vantage,
        observer=args.observer,
    )
    if args.statement:
        record = {
            "_type": STATEMENT_TYPE,
            "subject": [
                {
                    "name": args.implementation_name,
                    "digest": {"sha256": args.implementation_digest[len("sha256:") :]},
                }
            ],
            "predicateType": CLAIM_TYPE,
            "predicate": record,
        }
    text = json.dumps(record, indent=2, sort_keys=True) + "\n"
    if args.output is None:
        sys.stdout.write(text)
    else:
        if args.output.exists():
            raise FileExistsError(args.output)
        args.output.write_text(text, encoding="utf-8")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agent-evidence-vectors claim",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run", help="replay the frozen claim-record corpus into a new directory")
    run.add_argument("--corpus", type=Path, default=PACKAGED_CORPUS)
    run.add_argument("--output", type=Path, required=True)
    run.add_argument("--implementation-revision", default=None)
    run.set_defaults(func=_cmd_run)

    ver = sub.add_parser("verify", help="judge one record under an acceptance rule")
    ver.add_argument("--record", type=Path, required=True)
    ver.add_argument(
        "--rule",
        type=Path,
        required=True,
        help="the relying party's acceptance rule; it pins the profile and case sets",
    )
    ver.add_argument("--case-set", type=Path, action="append", default=[])
    ver.add_argument(
        "--profile",
        type=Path,
        action="append",
        default=[],
        help="a profile beyond the published ones; resolved by digest only",
    )
    ver.set_defaults(func=_cmd_verify)

    em = sub.add_parser("emit", help="build a conformance-profile record from a run's results")
    em.add_argument("--case-set", type=Path, required=True)
    em.add_argument(
        "--results",
        type=Path,
        required=True,
        help='JSON {"passed": [...], "failed": [...], "excluded": [{"id", "reason"}]}; '
        "every case it does not name is recorded as not run",
    )
    em.add_argument("--profile", type=Path, default=PACKAGED_CORPUS / "profiles/conformance.json")
    em.add_argument("--implementation-name", required=True)
    em.add_argument("--implementation-digest", required=True)
    em.add_argument("--verifier-name", required=True)
    em.add_argument("--verifier-digest", required=True)
    em.add_argument("--observation-vantage", choices=("substrate", "artifact"), required=True)
    em.add_argument("--observer", required=True)
    em.add_argument(
        "--statement",
        action="store_true",
        help="wrap the record as the predicate of an in-toto Statement v1",
    )
    em.add_argument("--output", type=Path, default=None)
    em.set_defaults(func=_cmd_emit)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return int(args.func(args))
    except (MalformedInput, OSError) as exc:
        print(f"claim: {exc}", file=sys.stderr)
        return EXIT_UNUSABLE


if __name__ == "__main__":
    raise SystemExit(main())
