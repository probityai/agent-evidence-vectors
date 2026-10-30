"""The logic behind the root action.yml: install the pinned tools, then check evidence.

    python3 run.py install-opa <dest-dir>
    python3 run.py install-checker <venv-dir>
    python3 run.py digest --python <py> --document <path> --artifact <path> [--artifact ...]
    python3 run.py policy --opa <opa> --rules <name> --statement <path> [--statement ...] [--pins <path>]
    python3 run.py coverage --document <path> --required <path>

`digest` runs the published agent-evidence-admission checker once per artifact. `policy`
evaluates every statement against one rule set of packages/admission/rego in a single opa
call. `coverage` runs the checker's coverage-check from this checkout's own source (standard
library only, so there is nothing to install) and reports one row per required class. Both write `result` (`admitted` or `refused`) and `refusals` (a count) to
GITHUB_OUTPUT and a table to GITHUB_STEP_SUMMARY when those are set, and exit 0 when
everything is admitted, 1 when anything is refused, 2 when an input could not be read or a
tool failed. Every tool is pinned in pins.json by version and SHA-256. Standard library
only, because it runs before anything is installed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

HERE = Path(__file__).resolve().parent
PINS = json.loads((HERE / "pins.json").read_text())
REGO_DIR = HERE.parents[1] / "packages" / "admission" / "rego"
CHECKER_SRC = HERE.parents[1] / "packages" / "admission" / "python" / "src"
NO_REASON = "refused: isCompliant is false and the rules named no reason in errors"
CONTRADICTION = "refused: isCompliant is true but the rules also named errors"


class SetupError(Exception):
    """An input could not be read or a tool did not run; the verdict is unknown."""


@dataclass
class Row:
    subject: str
    admitted: bool
    reasons: list[str] = field(default_factory=list)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def install_opa(dest: Path, platform: str) -> Path:
    """Download the pinned opa for this runner and refuse bytes that miss the pinned digest."""
    asset = PINS["opa"]["assets"].get(platform)
    if asset is None:
        known = ", ".join(sorted(PINS["opa"]["assets"]))
        raise SetupError(f"no pinned opa for runner {platform!r} (pinned: {known})")
    url = f"https://github.com/open-policy-agent/opa/releases/download/{PINS['opa']['version']}/{asset['file']}"
    dest.mkdir(parents=True, exist_ok=True)
    target = dest / "opa"
    with urllib.request.urlopen(url, timeout=120) as response:
        target.write_bytes(response.read())
    got = _sha256(target)
    if got != asset["sha256"]:
        target.unlink()
        raise SetupError(f"{url} has sha256 {got}, not the pinned {asset['sha256']}")
    target.chmod(0o755)
    return target


def install_checker(venv: Path) -> Path:
    """Install the pinned checker wheel into its own venv, hash-checked, and return its python."""
    # Tool chatter goes to stderr: stdout carries only the path the action.yml step reads.
    subprocess.run([sys.executable, "-m", "venv", str(venv)], check=True, stdout=sys.stderr)
    python = venv / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    lock = venv / "checker.lock"
    lock.write_text(f"{PINS['checker']['requirement']} --hash=sha256:{PINS['checker']['sha256']}\n")
    subprocess.run([str(python), "-m", "pip", "install", "--quiet", "--disable-pip-version-check",
                    "--no-deps", "--require-hashes", "--only-binary=:all:", "-r", str(lock)],
                   check=True, stdout=sys.stderr)
    return python


def check_digests(python: str, document: str, artifacts: list[str]) -> list[Row]:
    """Run the checker once per artifact; exit 2 from it means the verdict is unknown."""
    rows = []
    for artifact in artifacts:
        done = subprocess.run([python, "-m", "agent_evidence_admission.cli", "digest-check", document, artifact],
                              check=False, capture_output=True, text=True)
        line = (done.stdout or done.stderr).strip()
        if done.returncode not in (0, 1):
            raise SetupError(f"digest-check {artifact}: exit {done.returncode}: {line}")
        rows.append(Row(artifact, done.returncode == 0, [] if done.returncode == 0 else [line]))
    return rows


def check_coverage(document: str, required: str) -> list[Row]:
    """Run coverage-check from this checkout; one row per required class, refused when it fails."""
    env = {**os.environ, "PYTHONPATH": str(CHECKER_SRC)}
    done = subprocess.run([sys.executable, "-m", "agent_evidence_admission.cli", "coverage-check", document,
                           "--required", required, "--json"], check=False, capture_output=True, text=True, env=env)
    if done.returncode not in (0, 1):
        raise SetupError(f"coverage-check {document}: exit {done.returncode}: {(done.stderr or done.stdout).strip()}")
    try:
        classes = json.loads(done.stdout)["classes"]
    except (KeyError, ValueError) as error:
        raise SetupError(f"coverage-check printed no report: {done.stdout[:2000]}") from error
    failing = {"MISSING", "DOUBLE", "NO-REASON", "NOT-COMPLETE"}
    return [Row(f"{c['class']} {c['status']}", c["status"] not in failing,
                [c["detail"]] if c["status"] in failing else []) for c in classes]


def _read_json(path: str) -> object:
    try:
        return json.loads(Path(path).read_text())
    except (OSError, ValueError) as error:
        raise SetupError(f"could not read {path}: {error}") from error


def evaluate(opa: str, rules: str, statements: list[object], pins: object | None) -> list[tuple[bool, list[str]]]:
    """Evaluate each statement against one rule set in one opa call: (compliant, reasons)."""
    rule = PINS["rules"].get(rules)
    if rule is None:
        raise SetupError(f"unknown rules {rules!r} (known: {', '.join(sorted(PINS['rules']))})")
    pkg = rule["package"]
    query = (f"[r | some i; s := data.agent_evidence_action.statements[i]; "
             f"c := data.{pkg}.isCompliant with input as s; "
             f"e := data.{pkg}.errors with input as s; "
             f'r := {{"compliant": c, "reasons": sort(e)}}]')
    with tempfile.TemporaryDirectory() as tmp:
        batch = Path(tmp) / "statements.json"
        batch.write_text(json.dumps({"agent_evidence_action": {"statements": statements}}))
        argv = [opa, "eval", "--format", "json", "-d", str(REGO_DIR / rule["module"]),
                "-d", str(batch)]
        if pins is not None:
            data = Path(tmp) / "pins.json"
            data.write_text(json.dumps(pins))
            argv += ["-d", str(data)]
        done = subprocess.run([*argv, query], check=False, capture_output=True, text=True)
    if done.returncode != 0:
        raise SetupError(f"opa eval exit {done.returncode}: {(done.stderr or done.stdout).strip()[:2000]}")
    try:
        results = json.loads(done.stdout)["result"][0]["expressions"][0]["value"]
    except (KeyError, IndexError, ValueError) as error:
        raise SetupError(f"opa eval returned no decision: {done.stdout[:2000]}") from error
    if len(results) != len(statements):
        raise SetupError(f"opa decided {len(results)} of {len(statements)} statements")
    return [(r["compliant"] is True, list(r["reasons"])) for r in results]


def check_policy(opa: str, rules: str, paths: list[str], pins_path: str | None) -> list[Row]:
    statements = [_read_json(p) for p in paths]
    pins = _read_json(pins_path) if pins_path else None
    rows = []
    for path, (compliant, reasons) in zip(paths, evaluate(opa, rules, statements, pins)):
        if not compliant and not reasons:
            # A refusal is never reported without words: some rules refuse through
            # isCompliant alone, with nothing in errors to say why.
            reasons = [NO_REASON]
        elif compliant and reasons:
            reasons = [CONTRADICTION, *reasons]
        rows.append(Row(path, compliant and len(reasons) == 0, reasons))
    return rows


def _cell(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")


def report(title: str, rows: list[Row]) -> int:
    refused = [r for r in rows if not r.admitted]
    for row in rows:
        print(f"{'ADMIT' if row.admitted else 'REFUSE'} {row.subject}")
        for reason in row.reasons:
            print(f"  {reason}")
    print(f"{len(rows) - len(refused)} of {len(rows)} admitted")
    if out := os.environ.get("GITHUB_OUTPUT"):
        with open(out, "a") as handle:
            handle.write(f"result={'refused' if refused else 'admitted'}\nrefusals={len(refused)}\n")
    if summary := os.environ.get("GITHUB_STEP_SUMMARY"):
        lines = [f"### {title}: {len(rows) - len(refused)} of {len(rows)} admitted", "",
                 "| subject | decision | reasons |", "| --- | --- | --- |"]
        lines += [f"| `{_cell(r.subject)}` | {'admitted' if r.admitted else 'refused'} | "
                  f"{_cell('; '.join(r.reasons)) or '-'} |" for r in rows]
        with open(summary, "a") as handle:
            handle.write("\n".join(lines) + "\n")
    return 1 if refused else 0


def _paths(values: list[str]) -> list[str]:
    """Each value may hold several newline-separated paths, as an Action input does."""
    found = [line.strip() for value in values for line in value.splitlines() if line.strip()]
    if not found:
        raise SetupError("no path given")
    return found


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="run.py")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("install-opa").add_argument("dest")
    commands.add_parser("install-checker").add_argument("venv")
    digest = commands.add_parser("digest")
    digest.add_argument("--python", required=True)
    digest.add_argument("--document", required=True)
    digest.add_argument("--artifact", action="append", required=True)
    coverage = commands.add_parser("coverage")
    coverage.add_argument("--document", required=True)
    coverage.add_argument("--required", required=True)
    policy = commands.add_parser("policy")
    policy.add_argument("--opa", required=True)
    policy.add_argument("--rules", required=True)
    policy.add_argument("--statement", action="append", required=True)
    policy.add_argument("--pins")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "install-opa":
            platform = f"{os.environ.get('RUNNER_OS', '')}-{os.environ.get('RUNNER_ARCH', '')}"
            print(install_opa(Path(args.dest), platform))
            return 0
        if args.command == "install-checker":
            print(install_checker(Path(args.venv)))
            return 0
        if args.command == "digest":
            return report("digest check", check_digests(args.python, args.document, _paths(args.artifact)))
        if args.command == "coverage":
            return report("coverage check", check_coverage(args.document, args.required))
        return report(f"{args.rules} rules",
                      check_policy(args.opa, args.rules, _paths(args.statement), args.pins or None))
    except (SetupError, OSError, subprocess.CalledProcessError) as error:
        print(f"ERROR {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
