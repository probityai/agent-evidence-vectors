#!/usr/bin/env python3
"""Build and check installed readers; keep full original inputs and child results."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
import subprocess
import stat
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
STEMS = ("revocation-trace-local-20261004T122943Z", "revocation-trace-testnet-20261004T153434Z", "revocation-trace-testnet-20261005T022948Z")


def sha(path):
    value = hashlib.sha256()
    with path.open("rb") as stream:
        while block := stream.read(1 << 20): value.update(block)
    return value.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--upstream", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    if output.is_relative_to(ROOT) or output.exists():
        raise ValueError("select a new output directory outside source")
    output.mkdir(parents=True, mode=0o700)
    # Explicit measured qualification policy; hosts choose their own limits.
    policy = {"input_bytes": 1 << 20, "events": 256, "native_calls": 257, "native_output_bytes": 2 << 20, "capture_bytes": 4 << 20, "capture_files": 2048}
    limits = output / "limits.json"
    limits.write_text(json.dumps(policy, sort_keys=True) + "\n")
    ledger = []
    def capture(name, argv, cwd, env=None):
        start = time.monotonic()
        with (output / (name + ".stdout")).open("wb") as stdout, (output / (name + ".stderr")).open("wb") as stderr:
            child = subprocess.run(argv, cwd=cwd, env=env, stdout=stdout, stderr=stderr)
        row = {"name": name, "argv": list(map(str, argv)), "cwd": str(cwd), "native_exit": child.returncode, "elapsed_seconds": time.monotonic() - start, "stdout_sha256": sha(output / (name + ".stdout")), "stderr_sha256": sha(output / (name + ".stderr"))}
        ledger.append(row); (output / "steps.json").write_text(json.dumps(ledger, indent=2) + "\n")
        if child.returncode != 0: raise ValueError(f"actual step failed: {name}: {child.returncode}")
        return (output / (name + ".stdout")).read_bytes()
    capture("source-head", ["git", "rev-parse", "HEAD", "HEAD^{tree}"], ROOT)
    if capture("source-status", ["git", "status", "--porcelain=v1", "--untracked-files=all"], ROOT):
        raise ValueError("source checkout is not clean")
    capture("go-version", ["go", "version"], ROOT)
    capture("rust-version", ["rustc", "--version"], ROOT)
    capture("python-version", [sys.executable, "--version"], ROOT)
    capture("cargo-format", ["cargo", "fmt", "--check"], ROOT)
    capture("cargo-test", ["cargo", "test", "--locked"], ROOT)
    capture("cargo-clippy", ["cargo", "clippy", "--locked", "--all-targets", "--", "-D", "warnings"], ROOT)
    capture("cargo-doc", ["cargo", "doc", "--locked", "--no-deps"], ROOT, dict(os.environ, RUSTDOCFLAGS="-D warnings"))
    capture("go-admission-format", ["cargo", "fmt", "--manifest-path", "interop/go-jcs/admission/Cargo.toml", "--check"], ROOT)
    capture("go-admission-clippy", ["cargo", "clippy", "--locked", "--manifest-path", "interop/go-jcs/admission/Cargo.toml", "--all-targets", "--", "-D", "warnings"], ROOT)
    capture("go-pin-controls", [sys.executable, "-m", "unittest", "discover", "-s", "interop/go-jcs", "-p", "test_check.py"], ROOT)
    selection = json.loads((HERE / "SOURCE-SELECTION.json").read_bytes())
    for member in selection["files"]:
        path = HERE / member["path"]; raw = path.read_bytes()
        blob = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
        if len(raw) != member["bytes"] or sha(path) != member["sha256"] or blob != member["git_blob"]:
            raise ValueError("selected original differs: " + member["path"])
    capture("go-corpus", [sys.executable, str(ROOT / "interop/go-jcs/check.py"), "--upstream", str(args.upstream.resolve()), "--installation", str(output / "commands"), "--output", str(output / "go-report.json")], ROOT)
    capture("build-wheel", ["uv", "build", "--wheel", "--out-dir", str(output / "wheels"), str(HERE)], ROOT)
    capture("reader-environment", ["uv", "venv", "--python", sys.executable, str(output / "reader")], ROOT)
    wheels = list((output / "wheels").glob("*.whl"))
    if len(wheels) != 1: raise ValueError("one reader wheel required")
    python = output / "reader/bin/python"
    capture("install-wheel", ["uv", "pip", "install", "--python", str(python), "--no-deps", str(wheels[0])], output)
    probe = 'import importlib.metadata,json,mintid_trace.reader; from pathlib import Path; p=Path(mintid_trace.reader.__file__).parent; print(json.dumps({"version":importlib.metadata.version("jcs-mintid-trace-reader"),"root":str(p),"files":{name:(p/name).read_bytes().hex() for name in ("__init__.py","__main__.py","reader.py")}}))'
    installed = json.loads(capture("installed-source", [str(python), "-c", probe], output))
    if Path(installed["root"]).resolve().is_relative_to(ROOT): raise ValueError("reader imported source checkout")
    if installed["version"] != "0.1.0": raise ValueError("installed package version differs")
    for name, encoded in installed["files"].items():
        if bytes.fromhex(encoded) != (HERE / "mintid_trace" / name).read_bytes(): raise ValueError("installed source differs: " + name)
    original_results = []
    (output / "original-captures").mkdir(mode=0o700)
    for stem in STEMS:
        row = json.loads(capture(stem, [str(python), "-m", "mintid_trace", "--records", str(HERE / "upstream/records"), "--record", stem, "--go", str(output / "commands/go-jcs"), "--admission", str(output / "commands/go-jcs-admission"), "--capture-dir", str(output / "original-captures" / stem), "--limits", str(limits)], output))
        original_results.append({"record": stem, "status": row["status"], "event_count": row["event_count"], "decision_count": row["decision_count"], "source": row["source"], "policy": row["policy"], "stated": row["stated"], "admission_calls": len(row["admission_calls"]), "resource_usage": row["resource_usage"]})
    environment = dict(os.environ, MINTID_RECORDS=str(HERE / "upstream/records"), MINTID_GO=str(output / "commands/go-jcs"), MINTID_ADMISSION=str(output / "commands/go-jcs-admission"), MINTID_CAPTURE_ROOT=str(output / "control-captures"), MINTID_CONTROL_RESULTS=str(output / "control-results.json"))
    capture("installed-controls", [str(python), str(HERE / "tests/run_controls.py")], output, environment)
    if capture("source-status-after", ["git", "status", "--porcelain=v1", "--untracked-files=all"], ROOT):
        raise ValueError("source checkout changed during qualification")
    results = {"schema": "jcs-admit.mintid-qualification.v1", "source_selection_sha256": sha(HERE / "SOURCE-SELECTION.json"), "limits_sha256": sha(limits), "limits": policy, "wheel_sha256": sha(wheels[0]), "installed_import_outside_source": True, "installed_source_bytes_equal": True, "original_results": original_results, "control_results": json.loads((output / "control-results.json").read_bytes()), "steps": ledger, "scope": "Author-operated source-pinned installed-reader checks; no host acceptance, independent operator, chain verification or external effects"}
    (output / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    files, special = [], []
    for path in sorted(output.rglob("*")):
        if path.is_relative_to(output / "reader") or path.name == "ARTIFACTS.json": continue
        info = path.lstat()
        if stat.S_ISREG(info.st_mode):
            files.append({"path": str(path.relative_to(output)), "bytes": info.st_size, "sha256": sha(path)})
        elif not stat.S_ISDIR(info.st_mode):
            member = {"path": str(path.relative_to(output)), "mode": info.st_mode, "bytes": info.st_size}
            if stat.S_ISLNK(info.st_mode): member["link_target"] = os.readlink(path)
            special.append(member)
    (output / "ARTIFACTS.json").write_text(json.dumps({"schema": "jcs-admit.mintid-capture.v1", "files": files, "special_control_members_not_opened": special}, indent=2) + "\n")
    print(json.dumps({"original_records": len(original_results), "installed_controls": results["control_results"]["tests_run"], "whole_go_cases": 1263, "full_capture_members": len(files)}))


if __name__ == "__main__":
    main()
