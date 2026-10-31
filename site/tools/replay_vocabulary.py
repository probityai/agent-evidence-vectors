#!/usr/bin/env python3
"""Replay the retained native packet through a source-bound installed reader offline.

The command validates the selected Atlas register before creating an output
folder or installing a wheel. It makes no model calls and grants no action
permission. Default quality refusal is an expected, recorded result.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import venv
import zipfile
from pathlib import Path
from typing import Any

if __package__:
    from .check_lab import validate_register
    from .check_vocabulary_retention import HASHES, IDENTITY, encode
else:
    from check_lab import validate_register
    from check_vocabulary_retention import HASHES, IDENTITY, encode

ROOT = Path(__file__).resolve().parents[1]


def replay(root: Path, output: Path) -> dict[str, Any]:
    """Install only validated wheel bytes and retain actual child streams and decisions."""
    register = json.loads((root / "data/lab-register.json").read_bytes())
    if not any(record["id"] == IDENTITY for record in register["records"]):
        raise ValueError("vocabulary selected record is absent")
    validate_register(register, root)
    source = root / "experiments" / IDENTITY
    # Freeze all validated inputs in memory before creating files or a subprocess.
    frozen = {name: (source / name).read_bytes() for name in HASHES}
    if any(hashlib.sha256(raw).hexdigest() != HASHES[name] for name, raw in frozen.items()):
        raise ValueError("vocabulary source-bound bytes changed after validation")
    installed = json.loads(frozen["installed-replay.json"])
    native = json.loads(frozen["native-report.json"])
    output.mkdir(parents=True, exist_ok=False)
    with tempfile.TemporaryDirectory(prefix="probity-vocabulary-replay-") as temporary:
        work = Path(temporary)
        packet = work / "packet"
        packet.mkdir()
        with zipfile.ZipFile(io.BytesIO(frozen["original-artifact.zip"])) as bundle:
            for name in bundle.namelist():
                target = packet / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(bundle.read(name))
        pins = work / "host-pins.json"
        pins.write_bytes(encode(installed["hostPins"]))
        wheel_name = installed["wheel"]["name"]
        with zipfile.ZipFile(io.BytesIO(frozen["installed-capsule.zip"])) as capsule:
            wheel = work / wheel_name
            wheel.write_bytes(capsule.read("installed-original/wheel/" + wheel_name))
        environment = work / "environment"
        venv.EnvBuilder(with_pip=True).create(environment)
        python = environment / "bin/python"
        child_env = dict(os.environ)
        child_env.pop("PYTHONPATH", None)
        child_env.pop("PYTHONHOME", None)
        child_env["PYTHONNOUSERSITE"] = "1"
        installation = subprocess.run(
            [str(python), "-I", "-m", "pip", "--isolated", "install", "--no-input",
             "--no-deps", "--no-index", str(wheel)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=child_env, timeout=120,
        )
        if installation.returncode:
            raise ValueError("source-bound offline wheel installation failed")
        runtime = subprocess.run(
            [str(python), "-I", "-c", "import importlib.util,sys; assert importlib.util.find_spec('llama_cpp') is None; print(sys.version)"],
            capture_output=True, check=True, env=child_env, timeout=30,
        )
        observations = {}
        def consume(name: str, selected_packet: Path, expected_exit: int,
                    expected_decision: str, *extra: str) -> dict[str, Any]:
            child = subprocess.run(
                [str(python), "-I", "-m", "probity_policy_vocabulary_reader.cli",
                 str(selected_packet), "--pins-file", str(pins), *extra],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=child_env, timeout=120,
            )
            (output / (name + ".stdout.json")).write_bytes(child.stdout)
            (output / (name + ".stderr.txt")).write_bytes(child.stderr)
            result = json.loads(child.stdout)
            if child.returncode != expected_exit or result["consumerDecision"] != expected_decision:
                raise ValueError("installed replay differs from the declared consumer outcome")
            observations[name] = {
                "exitCode": child.returncode, "consumerDecision": result["consumerDecision"],
                "stdoutSHA256": hashlib.sha256(child.stdout).hexdigest(),
                "stderrSHA256": hashlib.sha256(child.stderr).hexdigest(),
            }
            return result
        first = consume("actual", packet, 1, "hold-quality")
        second = consume("actual-repeat", packet, 1, "hold-quality")
        evidence_only = consume("actual-evidence-only", packet, 0, "hold-quality", "--evidence-only")
        if any(encode(result["report"]) != encode(native) or
               result["evidenceDecision"] != "accept-scoped-evidence" or
               len(result["qualityFailures"]) != 8 for result in (first, second, evidence_only)):
            raise ValueError("installed replay changed complete native scores or quality failures")
        repeated_exact = (output / "actual.stdout.json").read_bytes() == (output / "actual-repeat.stdout.json").read_bytes()
        if not repeated_exact:
            raise ValueError("installed repeated replay changed stdout bytes")
        altered = work / "changed-terminal"
        shutil.copytree(packet, altered)
        terminal = json.loads((altered / "terminal.json").read_bytes())
        terminal["elapsed_ns"] += 1
        (altered / "terminal.json").write_bytes(encode(terminal))
        consume("changed-terminal", altered, 1, "hold-evidence")
        receipt = {
            "schema": "probity-atlas-installed-vocabulary-replay-v1",
            "sourceContractSHA256": HASHES["source-contract.json"],
            "originalArtifactSHA256": HASHES["original-artifact.zip"],
            "wheel": installed["wheel"], "modelRuntimeInstalled": False,
            "python": runtime.stdout.decode().strip(), "hostPins": installed["hostPins"],
            "repeatStdoutExact": repeated_exact, "observations": observations,
            "nativeInferenceCalls": 0,
            "scope": "Source-bound offline replay by the same operator; no outside acceptance, recurring adoption, effects or independent custody.",
        }
        (output / "receipt.json").write_bytes(encode(receipt))
        return receipt


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    receipt = replay(ROOT, args.output.resolve())
    print(encode(receipt).decode(), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
