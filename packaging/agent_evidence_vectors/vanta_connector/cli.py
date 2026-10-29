"""Push verifier pass/fail into Vanta as a custom resource.

    agent-evidence-vectors-vanta schema
    agent-evidence-vectors-vanta push [--corpus NAME ... | --vectors DIR ... | --report FILE ...]

``schema`` prints what to create once in the Vanta Dashboard: the custom resource definition
and the Custom Test rule (Vanta has no API for either). ``push`` runs the pinned reference
rail over each named corpus or bundle directory (or reads a report it already wrote), builds
the Vanta records, and prints the exact HTTP requests. It sends nothing unless ``--send`` is
given, and then reads VANTA_CLIENT_ID, VANTA_CLIENT_SECRET and VANTA_RESOURCE_ID from the
environment. One push carries every record: Vanta treats each PUT as the full state.

Exit status: 0 done, 1 a push failed or (with --fail-on-fail) a corpus failed, 2 unusable input.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from datetime import UTC, datetime
from importlib import metadata
from pathlib import Path
from typing import Any

from . import client
from .payloads import (
    CUSTOM_TEST_DESCRIPTION,
    CUSTOM_TEST_NAME,
    CUSTOM_TEST_RULE,
    DEFAULT_API_BASE,
    DEFAULT_EXTERNAL_URL,
    JTD_SCHEMA,
    ReportError,
    plan_requests,
    record_from_report,
    resource_body,
)

DISTRIBUTION = "agent-evidence-vectors"
EXIT_OK, EXIT_FAILED, EXIT_UNUSABLE = 0, 1, 2
RAIL_TIMEOUT_SECONDS = 1800
ENV_NAMES = ("VANTA_CLIENT_ID", "VANTA_CLIENT_SECRET", "VANTA_RESOURCE_ID")


def find_rail() -> Path:
    """The reference rail: beside this package in the wheel, one level up in a checkout."""
    here = Path(__file__).resolve()
    for candidate in (here.parents[1] / "run_vectors.py", here.parents[2] / "run_vectors.py"):
        if candidate.is_file():
            return candidate
    raise FileNotFoundError("the reference rail (run_vectors.py) was not found")


def package_version() -> str:
    try:
        return metadata.version(DISTRIBUTION)
    except metadata.PackageNotFoundError:
        return "checkout"


def run_rail(selector: list[str], verifier: str | None) -> dict[str, Any]:
    """Run the rail with the given corpus selector and return the report it wrote."""
    with tempfile.TemporaryDirectory(prefix="aev-vanta-") as tmp:
        report = Path(tmp) / "conformance-report.json"
        command = [sys.executable, str(find_rail()), *selector, "--report", str(report)]
        if verifier:
            command += ["--verifier", verifier]
        done = subprocess.run(  # noqa: S603 - fixed argv, no shell
            command,
            cwd=tmp,
            capture_output=True,
            text=True,
            timeout=RAIL_TIMEOUT_SECONDS,
            check=False,
        )
        if not report.is_file():
            tail = (done.stderr or done.stdout).strip()[-400:]
            raise ReportError(f"the rail exited {done.returncode} and wrote no report: {tail}")
        loaded: dict[str, Any] = json.loads(report.read_text(encoding="utf-8"))
        return loaded


def read_report(path: str) -> dict[str, Any]:
    try:
        loaded: dict[str, Any] = json.loads(Path(path).read_text(encoding="utf-8"))
        return loaded
    except (OSError, ValueError) as error:
        raise ReportError(f"cannot read report {path}: {error}") from None


def collect_reports(args: argparse.Namespace) -> list[dict[str, Any]]:
    reports = [read_report(p) for p in args.report]
    reports += [run_rail(["--vectors", d], args.verifier) for d in args.vectors]
    corpora = args.corpus or ([] if reports else ["vectors"])
    reports += [run_rail(["--corpus", c], args.verifier) for c in corpora]
    return reports


def cmd_schema() -> int:
    print("Create once in Vanta (Developer Console, Build Integrations, Private app):")
    print("1. Resources tab, Add resource, Custom resource. Paste this schema, save, copy the ID.")
    print(json.dumps(JTD_SCHEMA, indent=2))
    print("2. Tests page, + Create custom test. Pick the private integration and this resource.")
    print(f"   Name: {CUSTOM_TEST_NAME}")
    print(f"   Description: {CUSTOM_TEST_DESCRIPTION}")
    print(f"   Pass rule: {CUSTOM_TEST_RULE}")
    print("3. Export VANTA_CLIENT_ID, VANTA_CLIENT_SECRET and VANTA_RESOURCE_ID, then push --send.")
    return EXIT_OK


def send(api_base: str, records: list[dict[str, Any]]) -> None:
    missing = [name for name in ENV_NAMES if not os.environ.get(name)]
    if missing:
        raise client.VantaError("set " + ", ".join(missing) + " in the environment to --send")
    base = client.check_base(api_base)
    token = client.request_token(
        base, os.environ["VANTA_CLIENT_ID"], os.environ["VANTA_CLIENT_SECRET"]
    )
    body = resource_body(os.environ["VANTA_RESOURCE_ID"], records)
    counts = client.put_resources(base, token, body)
    print(f"vanta accepted {counts['accepted']} record(s), rejected {counts['rejected']}")


def build_records(args: argparse.Namespace) -> list[dict[str, Any]]:
    reports = collect_reports(args)
    stamp = args.run_timestamp or datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    version = package_version()
    return [
        record_from_report(
            r, run_timestamp=stamp, package_version=version, external_url=args.external_url
        )
        for r in reports
    ]


def cmd_push(args: argparse.Namespace) -> int:
    try:
        records = build_records(args)
    except (ReportError, OSError, ValueError, subprocess.SubprocessError) as error:
        print(f"vanta connector: {error}", file=sys.stderr)
        return EXIT_UNUSABLE
    for record in records:
        props = record["customProperties"]
        verdict = f"allPass={props['allPass']} pass={props['pass']}/{props['vectors']}"
        print(f"{record['uniqueId']}: {verdict}")
    if args.send:
        try:
            send(args.api_base, records)
        except client.VantaError as error:
            print(f"vanta connector: {error}", file=sys.stderr)
            return EXIT_FAILED
    else:
        resource_id = os.environ.get("VANTA_RESOURCE_ID", "<VANTA_RESOURCE_ID>")
        for plan in plan_requests(args.api_base, resource_id, records):
            print("\n" + plan.render())
        print("\ndry run: nothing was sent; add --send to push")
    failed = any(not r["customProperties"]["allPass"] for r in records)
    return EXIT_FAILED if failed and args.fail_on_fail else EXIT_OK


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="agent-evidence-vectors-vanta", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("schema", help="print the Vanta Dashboard setup")
    push = sub.add_parser("push", help="build the records and push them (dry run by default)")
    push.add_argument("--corpus", action="append", default=[], help="shipped corpus name")
    push.add_argument("--vectors", action="append", default=[], help="bundle directory")
    push.add_argument("--report", action="append", default=[], help="a conformance-report.json")
    push.add_argument("--verifier", default=None, help="external verifier command line")
    push.add_argument("--send", action="store_true", help="really call the Vanta API")
    push.add_argument("--api-base", default=DEFAULT_API_BASE)
    push.add_argument("--external-url", default=DEFAULT_EXTERNAL_URL)
    push.add_argument(
        "--run-timestamp", default=None, help="fixed UTC time, for reproducible output"
    )
    push.add_argument("--fail-on-fail", action="store_true", help="exit 1 if any corpus fails")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return cmd_schema() if args.command == "schema" else cmd_push(args)


if __name__ == "__main__":
    sys.exit(main())
