"""Compare a pinned directory of supplied signed actions with its expectations."""

import argparse
import hashlib
import importlib.metadata
import json
import platform
import re
import subprocess
from pathlib import Path

from reader import assess, decode_json

CASE_NAME = re.compile(r"[a-z0-9_]+")
VECTORS_VERSION = "0.17.6"


def _expectation(row) -> None:
    expected = row.get("expect") if isinstance(row, dict) else None
    if not isinstance(expected, dict) or set(expected) != {
        "verdict",
        "refusals",
        "findings",
    }:
        raise ValueError("expected signature shape is malformed")
    if expected["verdict"] not in ("accepted", "refused"):
        raise ValueError("unsupported is not a passing expectation")
    for field in ("refusals", "findings"):
        values = expected[field]
        if not isinstance(values, list) or any(not isinstance(v, str) for v in values):
            raise ValueError("expected diagnostic list is malformed")
        if values != sorted(set(values)):
            raise ValueError("expected diagnostic list is not sorted and unique")


def _population(corpus: Path) -> tuple[dict, bytes]:
    expected_path = corpus / "expected.json"
    raw = expected_path.read_bytes()
    expected = decode_json(raw)
    cases = expected.get("cases") if isinstance(expected, dict) else None
    if not isinstance(cases, dict) or not cases:
        raise ValueError("expected case population is empty or malformed")
    if any(
        not isinstance(name, str) or not CASE_NAME.fullmatch(name) for name in cases
    ):
        raise ValueError("case name is not a safe file basename")
    presented = {path.stem for path in (corpus / "fixtures").glob("*.json")}
    if presented != set(cases):
        raise ValueError("fixture and expectation populations differ")
    for row in cases.values():
        _expectation(row)
    return cases, raw


def _pinned_inputs(
    corpus: Path, cases: dict, expected: bytes, pins: Path, pins_sha256: str
) -> tuple[dict, bytes]:
    raw = pins.read_bytes()
    if hashlib.sha256(raw).hexdigest() != pins_sha256:
        raise ValueError("pin manifest digest differs")
    manifest = decode_json(raw)
    names = {"fixtures/" + name + ".json" for name in cases} | {"expected.json"}
    if not isinstance(manifest, dict) or set(manifest) != names:
        raise ValueError("pin manifest population differs")
    inputs = {
        name: (corpus / name).read_bytes() for name in names if name != "expected.json"
    }
    inputs["expected.json"] = expected
    for name, data in inputs.items():
        if len(data) > 1024 * 1024:
            raise ValueError("input exceeds one MiB")
        if hashlib.sha256(data).hexdigest() != manifest[name]:
            raise ValueError("input digest differs: " + name)
    return inputs, raw


def _reader_identity() -> dict:
    here = Path(__file__).resolve().parent
    relative = here.relative_to(here.parents[1])
    revision = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=here,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    committed = subprocess.run(
        ["git", "show", revision + ":" + str(relative / "reader.py")],
        cwd=here,
        capture_output=True,
        check=False,
    )
    source = (here / "reader.py").read_bytes()
    runner = (here / "run_corpus.py").read_bytes()
    committed_runner = subprocess.run(
        ["git", "show", revision + ":" + str(relative / "run_corpus.py")],
        cwd=here,
        capture_output=True,
        check=False,
    )
    return {
        "readerCommit": revision
        if committed.returncode == 0 and committed.stdout == source
        else None,
        "readerSourceSHA256": hashlib.sha256(source).hexdigest(),
        "runnerCommit": revision
        if committed_runner.returncode == 0 and committed_runner.stdout == runner
        else None,
        "runnerSourceSHA256": hashlib.sha256(runner).hexdigest(),
    }


def replay(
    corpus: Path, pins: Path, pins_sha256: str, operator: str | None = None
) -> dict:
    """Refuse an incomplete or changed population before recording agreements."""
    cases, expected = _population(corpus)
    inputs, raw_pins = _pinned_inputs(corpus, cases, expected, pins, pins_sha256)
    version = importlib.metadata.version("agent-evidence-vectors")
    if version != VECTORS_VERSION:
        raise ValueError("Vectors version differs from the selected pin")
    rows = []
    for name in sorted(cases):
        raw = inputs["fixtures/" + name + ".json"]
        result = assess(decode_json(raw))
        rows.append(
            {
                "name": name,
                "inputSHA256": hashlib.sha256(raw).hexdigest(),
                "expected": cases[name]["expect"],
                "reader": result,
                "matches": result["signature"] == cases[name]["expect"],
            }
        )
    return {
        "schema": "probity.signed-action-presence-replay/v1",
        **_reader_identity(),
        "vectorsVersion": version,
        "pythonVersion": platform.python_version(),
        "expectationsSHA256": hashlib.sha256(expected).hexdigest(),
        "pinManifestSHA256": hashlib.sha256(raw_pins).hexdigest(),
        "operator": {
            "identity": operator,
            "source": "caller-declared",
            "authenticated": False,
        },
        "total": len(rows),
        "passed": sum(row["matches"] for row in rows),
        "cases": rows,
        "scope": "Offline comparison of the supplied finite corpus; operator identity is caller-declared; no live evidence lookup, runtime execution, admission or whole-SDK qualification.",
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", required=True, type=Path)
    parser.add_argument("--pins", required=True, type=Path)
    parser.add_argument("--pins-sha256", required=True)
    parser.add_argument("--operator")
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    report = replay(args.corpus, args.pins, args.pins_sha256, args.operator)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(
        json.dumps(
            {
                "passed": report["passed"],
                "total": report["total"],
                "readerCommit": report["readerCommit"],
            }
        )
    )
    return int(report["passed"] != report["total"])


if __name__ == "__main__":
    raise SystemExit(main())
