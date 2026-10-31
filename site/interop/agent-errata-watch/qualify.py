"""Qualify installed import and Verify readers against saved, pinned bytes."""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import os
import platform
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def captured(command: list[str], cwd: Path, environment: dict) -> dict:
    observed = subprocess.run(command, cwd=cwd, env=environment, capture_output=True, timeout=30, check=False)
    return {
        "exit": observed.returncode,
        "stdout_hex": observed.stdout.hex(),
        "stdout_sha256": sha(observed.stdout),
        "stderr_hex": observed.stderr.hex(),
        "stdout_bytes": len(observed.stdout),
    }


def _pin_raw(manifest: dict, raw: dict, role: str, value: dict) -> None:
    from test_import import repin

    repin(manifest, raw, role, value)


def _change(manifest: dict, raw: dict, transform, reported: bool) -> None:
    run = json.loads(raw["run/fixture"])
    transform(run["row"])
    run["changed"] = reported
    state = json.loads(raw["current_state"])
    state["harnesses"]["fixture"]["row"] = run["row"]
    _pin_raw(manifest, raw, "current_state", state)
    _pin_raw(manifest, raw, "run/fixture", run)


def _apply_control(name: str, manifest: dict, raw: dict) -> tuple[int, bool]:
    transforms = {
        "missed-membership-change": (lambda row: row["arms"].update(b=["replacement"]), False, 1, True),
        "false-change-match": (lambda _: None, True, 1, False),
        "arm-reorder": (lambda row: row["arms"]["a"].reverse(), False, 0, False),
        "symlink-key-reorder": (lambda row: row["sym"].update(e={"F": 2, "E": 1}), True, 0, False),
        "exact-token-boundary": (lambda row: row["s004"].update(total=110), False, 0, False),
        "beyond-token-boundary": (lambda row: row["s004"].update(total=111), True, 0, True),
        "missed-occurrence-change": (lambda row: row["sym"]["e"].update(E=2), False, 1, True),
    }
    if name in transforms:
        transform, reported, expected_exit, expected_changed = transforms[name]
        _change(manifest, raw, transform, reported)
        return expected_exit, expected_changed
    if name == "source-drift":
        raw["registry"] += b"drift"
        return 2, False
    if name in {"identity-substitution", "baseline-version-swap"}:
        run = json.loads(raw["run/fixture"])
        run["harness" if name == "identity-substitution" else "previous_version"] = "other"
        _pin_raw(manifest, raw, "run/fixture", run)
        return 2, False
    if name == "population-addition":
        manifest["population"].append("other")
        return 2, False
    if name == "duplicate-key":
        data = raw["run/fixture"][:-2] + b',"harness":"fixture"}\n'
        raw["run/fixture"] = data
        pin = next(item for item in manifest["files"] if item["role"] == "run/fixture")
        pin.update(bytes=len(data), sha256=sha(data), gitBlob=hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest())
        return 2, False
    if name == "zero-token-baseline":
        before = json.loads(raw["baseline_state"])
        before["harnesses"]["fixture"]["row"]["s004"]["total"] = 0
        _pin_raw(manifest, raw, "baseline_state", before)
    return 0, False


def finite_controls(build: Path, environment: dict, cwd: Path) -> list[dict]:
    from test_import import fixture, materialize
    from watch_import.reader import canonical

    names = [
        "clean",
        "missed-membership-change",
        "false-change-match",
        "arm-reorder",
        "symlink-key-reorder",
        "source-drift",
        "identity-substitution",
        "baseline-version-swap",
        "population-addition",
        "duplicate-key",
        "zero-token-baseline",
        "exact-token-boundary",
        "beyond-token-boundary",
        "missed-occurrence-change",
    ]
    rows = []
    for name in names:
        manifest, raw = fixture()
        expected_exit, expected_changed = _apply_control(name, manifest, raw)
        folder = build / "controls" / name
        folder.mkdir(parents=True, exist_ok=True)
        materialize(folder / "inputs", manifest, raw)
        sources = folder / "sources.json"
        sources.write_bytes(canonical(manifest))
        command = [sys.executable, "-m", "watch_import.cli", str(folder / "inputs"), "--sources", str(sources)]
        observed = captured(command, cwd, environment)
        actual = json.loads(bytes.fromhex(observed["stdout_hex"])) if observed["exit"] != 2 else None
        matched = observed["exit"] == expected_exit
        if actual is not None:
            matched = matched and actual["rows"][0]["comparison"]["changed"] == expected_changed
        rows.append(
            {
                "name": name,
                "scope": "synthetic finite saved-row mutation; no publisher or harness execution",
                "expected_exit": expected_exit,
                "expected_changed": None if expected_exit == 2 else expected_changed,
                "source_manifest_sha256": sha(sources.read_bytes()),
                "actual": observed,
                "matched": matched,
            }
        )
    return rows


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input-root", type=Path, required=True)
    parser.add_argument("--installation", type=Path, required=True)
    parser.add_argument("--verify-installation", type=Path, required=True)
    parser.add_argument("--sources", type=Path, default=HERE / "source-pins.json")
    parser.add_argument("--report", type=Path, default=HERE / "report.json")
    args = parser.parse_args()
    installation, verify_installation = args.installation.resolve(), args.verify_installation.resolve()
    sys.path.insert(0, str(installation))
    import watch_import.reader
    from watch_import import import_watch, strict_json

    if not Path(watch_import.reader.__file__).is_relative_to(installation):
        raise ValueError("API reader was not imported from the installation")
    manifest = strict_json(args.sources.read_bytes())
    for item in manifest["verify"]["files"]:
        if item["path"].startswith("src/"):
            if sha((verify_installation / item["path"].removeprefix("src/")).read_bytes()) != item["sha256"]:
                raise ValueError("installed Verify source differs from its selected pin")
    build = HERE / ".build"
    build.mkdir(exist_ok=True)
    outside = build / "outside-cwd"
    outside.mkdir(exist_ok=True)
    environment = {**os.environ, "PYTHONPATH": str(installation)}
    result, _ = import_watch(args.input_root.resolve(), manifest)
    bundle = build / "bundle"
    command = [
        sys.executable,
        "-m",
        "watch_import.cli",
        str(args.input_root.resolve()),
        "--sources",
        str(args.sources.resolve()),
        "--output",
        str(bundle),
    ]
    original = captured(command, outside, environment)
    actual = json.loads(bytes.fromhex(original["stdout_hex"]))
    original_equal = actual == result and original["exit"] == 0
    bridge = []
    verify_environment = {**os.environ, "PYTHONPATH": str(verify_installation)}
    for entry in json.loads((bundle / "bundle.json").read_bytes())["verify_bridge"]:
        if entry["status"] != "ready":
            bridge.append({**entry, "matched": False})
            continue
        observed = captured(
            [
                sys.executable,
                "-m",
                "probity_verify.cli",
                str(bundle / entry["case"]),
                "--policy",
                str(bundle / entry["candidate_policy"]),
                "--json",
            ],
            outside,
            verify_environment,
        )
        decision = json.loads(bytes.fromhex(observed["stdout_hex"]))
        folder = (bundle / entry["case"]).parent
        (folder / "decision.json").write_bytes(bytes.fromhex(observed["stdout_hex"]))
        bridge.append(
            {
                "harness": entry["harness"],
                "actual": observed,
                "decision": decision["decision"],
                "reason": decision["reason"],
                "matched": observed["exit"] == 0 and decision["decision"] == "supported",
            }
        )
    controls = finite_controls(build, environment, outside)

    def git(*parts: str) -> str:
        return subprocess.check_output(["git", *parts], cwd=HERE, text=True).strip()

    report = {
        "schema": "probity.watch-qualification/v1",
        "qualified_checkout": git("rev-parse", "HEAD"),
        "worktree_status": git("status", "--porcelain").splitlines(),
        "workflow_run_id": os.environ.get("GITHUB_RUN_ID"),
        "runtime": {"python": platform.python_version(), "setuptools": importlib.metadata.version("setuptools")},
        "source_manifest_sha256": sha(args.sources.read_bytes()),
        "source_revision": manifest["sourceRevision"],
        "baseline_revision": manifest["baselineRevision"],
        "verify_revision": manifest["verify"]["revision"],
        "installed_reader_sha256": sha(Path(watch_import.reader.__file__).read_bytes()),
        "installed_verify_core_sha256": sha((verify_installation / "probity_verify/core.py").read_bytes()),
        "original_import": result,
        "original_cli": original,
        "installed_api_cli_equal": original_equal,
        "verify_bridge": bridge,
        "controls": controls,
        "summary": {
            "original_rows": len(result["rows"]),
            "consistent_publisher_claims": result["summary"]["consistent_publisher_claims"],
            "adapter_changed": result["summary"]["adapter_changed"],
            "verify_cases": len(bridge),
            "verify_supported": sum(entry["matched"] for entry in bridge),
            "synthetic_controls": len(controls),
            "controls_matched": sum(entry["matched"] for entry in controls),
        },
        "scope": {
            "qualification_operator": "author-operated reader qualification",
            "harnesses_executed": False,
            "publisher_run_reproduced": False,
            "raw_model_request_captures": "not supplied by selected row files",
            "token_projection": "Verify recomputes importer-derived integer token deltas, not instruction membership or host execution.",
            "candidate_policy_accepted_by_outside_consumer": False,
            "host_required_action_adopted": False,
            "registered_study_change": False,
        },
    }
    args.report.write_text(json.dumps(report, indent=2, ensure_ascii=True) + "\n")
    print(json.dumps(report["summary"]))
    return 0 if original_equal and all(item["matched"] for item in controls + bridge) else 1


if __name__ == "__main__":
    raise SystemExit(main())
