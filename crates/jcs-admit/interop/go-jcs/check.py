#!/usr/bin/env python3
"""Qualify the installed raw-admission adapter against pinned Go JCS and bytes."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import struct
import subprocess
import tempfile
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def verify_files(root: Path, entries: list[dict[str, Any]]) -> None:
    """Check every byte pin before building or executing its source."""
    for entry in entries:
        raw = (root / entry["path"]).read_bytes()
        if len(raw) != entry["bytes"] or digest(raw) != entry["sha256"]:
            raise ValueError(f"pinned bytes differ: {entry['path']}")


def accepted(raw: bytes) -> dict[str, str]:
    return {"status": "accepted", "canonical_hex": raw.hex()}


def refused(error: str, stage: str = "raw-admission") -> dict[str, str]:
    return {"status": "refused", "error_class": error, "stage": stage}


def control_cases() -> list[dict[str, Any]]:
    """Declare finite inputs without deriving expected bytes from either writer."""
    cases: list[dict[str, Any]] = []

    def add(name: str, raw: bytes, expected: dict[str, str], profile: str = "rfc8785", **caps: int) -> None:
        cases.append({"name": "controls/" + name, "raw": raw, "expected": expected, "profile": profile, **caps})

    add("duplicate", b'{"a":1,"a":2}', refused("DuplicateMember"))
    add("escaped-duplicate", br'{"a":1,"\u0061":2}', refused("DuplicateMember"))
    add("lone-surrogate", br'["\ud800"]', refused("StringNotScalar"))
    add("mispaired-surrogates", br'["\ud800\ud800"]', refused("StringNotScalar"))
    add("utf8-surrogate", b'["\xed\xa0\x80"]', refused("StringNotScalar"))
    add("overlong-utf8", b'["\xc0\xaf"]', refused("StringNotScalar"))
    add("nonfinite", b'[1e309]', refused("NonFiniteNumber"))
    add("unsafe-integer-rfc", b'[9007199254740993]', accepted(b'[9007199254740992]'))
    add("unsafe-integer-ijson", b'[9007199254740993]', refused("UnsafeInteger"), "ijson")
    add("rounded-decimal-ijson", b'[9007199254740993.0]', refused("UnsafeInteger"), "ijson")
    add("safe-integer-ijson", b'[9007199254740991]', accepted(b'[9007199254740991]'), "ijson")
    add("fraction-ijson", b'[1.5]', accepted(b'[1.5]'), "ijson")
    add("fraction-integers", b'[1.5]', refused("NonIntegerNumber"), "ijson-integers")
    add("noncharacter-rfc", br'["\uffff"]', accepted('["\uffff"]'.encode()))
    add("noncharacter-ijson", br'["\uffff"]', refused("StringNotScalar"), "ijson")
    add("depth-at-cap", b'[[0]]', accepted(b'[[0]]'), max_depth=2)
    add("depth-past-cap", b'[[[0]]]', refused("TooDeep"), max_depth=2)
    add("size-at-cap", b'[0]' + b' ' * 61, accepted(b'[0]'), max_bytes=64)
    add("size-past-cap", b'[0]' + b' ' * 62, refused("TooLarge"), max_bytes=64)
    for name, raw in [("scalar-number", b'1'), ("scalar-string", b'"ok"'), ("scalar-boolean", b'true'), ("scalar-null", b'null')]:
        add(name, raw, refused("ObjectOrArrayRequired", "go-root-domain"))
    add("invalid-scalar-refuses-first", br'"\ud800"', refused("StringNotScalar"))
    add("trailing-content", b'{}{}', refused("TrailingContent"))
    add("utf16-order", '{"\ue000":1,"\U0001f600":2}'.encode(), accepted('{"\U0001f600":2,"\ue000":1}'.encode()))
    add("normalization-preserved", '{"e\u0301":1,"\u00e9":2}'.encode(), accepted('{"e\u0301":1,"\u00e9":2}'.encode()))
    return cases


def corpus_cases() -> list[dict[str, Any]]:
    """Use all original byte cases and explicitly adapted number containers."""
    cases: list[dict[str, Any]] = []
    for family, output, profile in [("rfc8785", "output", "rfc8785"), ("cross-rail", "canonical", "ijson-integers")]:
        base = ROOT / "tests/vectors" / family
        for path in sorted((base / output).glob("*.json")):
            cases.append({"name": f"{family}/{path.stem}", "raw": (base / "input" / path.name).read_bytes(), "expected": accepted(path.read_bytes()), "profile": profile})
    refusals = ROOT / "tests/vectors/cross-rail/refused.tsv"
    for line in refusals.read_text().splitlines():
        if line and not line.startswith("#"):
            name, error, _ = line.split("\t", 2)
            cases.append({"name": "cross-rail/" + name, "raw": (refusals.parent / "input" / (name + ".json")).read_bytes(), "expected": refused(error), "profile": "ijson-integers"})
    for line in (ROOT / "tests/vectors/attack/strings-keys-members.tsv").read_text().splitlines():
        if line and not line.startswith("#"):
            name, raw_hex, expected, *_ = line.split("\t")
            outcome = accepted(bytes.fromhex(expected.split(" ", 1)[1])) if expected.startswith("ACCEPT ") else {"status": "refused", "stage": "raw-admission"}
            raw = bytes.fromhex(raw_hex)
            native_expected = dict(outcome)
            if outcome["status"] == "accepted" and not raw.lstrip(b" \t\r\n").startswith((b"{", b"[")):
                outcome = refused("ObjectOrArrayRequired", "go-root-domain")
            cases.append({"name": "attack/" + name, "raw": raw, "expected": outcome, "native_expected": native_expected, "profile": "ijson-integers"})
    for i, line in enumerate((ROOT / "tests/vectors/es-number-ties.tsv").read_text().splitlines()):
        if line and not line.startswith("#"):
            token, expected, _ = line.split("\t")
            cases.append({"name": f"number-ties/line-{i + 1}", "raw": ("[" + token + "]").encode(), "expected": accepted(("[" + expected + "]").encode()), "profile": "rfc8785"})
    for line in (ROOT / "tests/vectors/rfc8785/appendix-b.tsv").read_text().splitlines():
        if line and not line.startswith("#"):
            bits, expected, _ = line.split("\t")
            if expected == "-":
                continue
            value = struct.unpack(">d", bytes.fromhex(bits))[0]
            token = repr(value)
            cases.append({"name": "appendix-b/" + bits, "raw": ("[" + token + "]").encode(), "expected": accepted(("[" + expected + "]").encode()), "profile": "rfc8785"})
    counts = {family: sum(c["name"].startswith(family + "/") for c in cases) for family in ["rfc8785", "cross-rail", "attack", "number-ties", "appendix-b"]}
    if counts != {"rfc8785": 6, "cross-rail": 39, "attack": 317, "number-ties": 850, "appendix-b": 24}:
        raise ValueError(f"pinned corpus counts differ: {counts}")
    return cases + control_cases()


def invoke(binary: Path, admission: Path, case: dict[str, Any], working: Path, bare: bool) -> dict[str, Any]:
    """Run installed commands outside the checkout; raw input goes through stdin."""
    command = [str(binary), "--bare"] if bare else [str(binary), "--admission", str(admission)]
    command.extend(["--profile", case["profile"], "--max-depth", str(case.get("max_depth", 128)), "--max-bytes", str(case.get("max_bytes", 20 << 20))])
    result = subprocess.run(command, input=case["raw"], cwd=working, capture_output=True, timeout=15, check=True)
    if result.stderr:
        raise ValueError(f"installed command emitted stderr: {case['name']}")
    return json.loads(result.stdout)


def require_outcome(actual: dict[str, Any], expected: dict[str, Any], name: str) -> None:
    if any(actual.get(key) != value for key, value in expected.items()):
        raise ValueError(f"consumer outcome differs: {name}: expected {expected}, actual {actual}")


def qualify(binary: Path, admission: Path) -> dict[str, Any]:
    records = []
    with tempfile.TemporaryDirectory(prefix="go-jcs-reader-") as directory:
        working = Path(directory)
        for case in corpus_cases():
            actual = invoke(binary, admission, case, working, bare=False)
            require_outcome(actual, case["expected"], case["name"])
            bare = invoke(binary, admission, case, working, bare=True)
            records.append({"name": case["name"], "profile": case["profile"], "max_depth": case.get("max_depth", 128), "max_bytes": case.get("max_bytes", 20 << 20), "input_sha256": digest(case["raw"]), "input_bytes": len(case["raw"]), "declared_native_expectation": case.get("native_expected"), "consumer": actual, "bare_go": bare})
    return {
        "schema": "jcs-admit.go-jcs.result.v1",
        "summary": {"cases": len(records), "consumer_exact_byte_matches": sum(r["consumer"]["status"] == "accepted" for r in records), "raw_admission_refusals": sum(r["consumer"]["stage"] == "raw-admission" for r in records), "scalar_domain_refusals": sum(r["consumer"]["stage"] == "go-root-domain" for r in records), "bare_go_observations": len(records)},
        "installed_commands": [{"name": p.name, "bytes": p.stat().st_size, "sha256": digest(p.read_bytes())} for p in [binary, admission]],
        "records": records,
    }


def build(installation: Path) -> tuple[Path, Path]:
    installation.mkdir(parents=True, exist_ok=True)
    subprocess.run(["cargo", "build", "--locked", "--manifest-path", str(HERE / "admission/Cargo.toml")], check=True, cwd=ROOT)
    admission = installation / "go-jcs-admission"
    admission.write_bytes((HERE / "admission/target/debug/go-jcs-admission").read_bytes())
    admission.chmod(0o755)
    binary = installation / "go-jcs"
    subprocess.run(["go", "build", "-trimpath", "-o", str(binary), "./cmd/qualify"], check=True, cwd=HERE)
    environment = dict(os.environ, GO_JCS_ADMISSION=str(admission))
    subprocess.run(["go", "test", "-count=1", ".", "./cmd/qualify", "./source/jsoncanonicalizer"], check=True, cwd=HERE, env=environment)
    return binary, admission


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--upstream", type=Path, default=HERE / "upstream")
    parser.add_argument("--installation", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=HERE / "report.json")
    args = parser.parse_args()
    manifest = json.loads((HERE / "MANIFEST.json").read_text())
    verify_files(args.upstream, manifest["go_source"]["files"])
    verify_files(ROOT, manifest["corpus"]["files"])
    for path in ["jsoncanonicalizer.go", "es6numfmt.go"]:
        if (HERE / "source/jsoncanonicalizer" / path).read_bytes() != (args.upstream / "go/src/webpki.org/jsoncanonicalizer" / path).read_bytes():
            raise ValueError("compiled Go source differs from its pinned original")
    if (HERE / "source/LICENSE").read_bytes() != (args.upstream / "LICENSE").read_bytes():
        raise ValueError("retained Go license differs")
    environment = dict(os.environ, GO111MODULE="off", GOPATH=str(args.upstream.resolve() / "go"))
    upstream = subprocess.run(["go", "run", str(args.upstream.resolve() / "go/test/verify-canonicalization.go")], check=True, capture_output=True, cwd=args.upstream, env=environment)
    if b"All tests succeeded!" not in upstream.stdout or b"FAILED" in upstream.stdout or b"ERRORS:" in upstream.stdout:
        raise ValueError("pinned Go native byte suite failed")
    args.installation.resolve().parent.mkdir(parents=True, exist_ok=True)
    (args.installation.resolve().parent / "go-upstream-native.log").write_bytes(upstream.stdout + upstream.stderr)
    binary, admission = build(args.installation.resolve())
    report = qualify(binary, admission)
    report["source"] = {"go": {k: v for k, v in manifest["go_source"].items() if k != "files"}, "corpus": {k: v for k, v in manifest["corpus"].items() if k != "files"}}
    report["adaptations"] = manifest["adaptations"]
    report["manifest_sha256"] = digest((HERE / "MANIFEST.json").read_bytes())
    report["runtime"] = {"go": subprocess.run(["go", "version"], check=True, capture_output=True, text=True).stdout.strip(), "rust": subprocess.run(["rustc", "--version"], check=True, capture_output=True, text=True).stdout.strip(), "python": platform.python_version()}
    report["qualified_checkout"] = subprocess.run(["git", "rev-parse", "HEAD"], check=True, capture_output=True, text=True, cwd=ROOT).stdout.strip()
    report["worktree_status"] = subprocess.run(["git", "status", "--porcelain", "--untracked-files=no"], check=True, capture_output=True, text=True, cwd=ROOT).stdout.splitlines()
    report["workflow_run_id"] = os.environ.get("GITHUB_RUN_ID")
    report["upstream_native"] = {"status": "passed", "source": "go/test/verify-canonicalization.go", "stdout_sha256": digest(upstream.stdout)}
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
