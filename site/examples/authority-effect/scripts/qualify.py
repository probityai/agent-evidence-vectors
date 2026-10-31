"""Check selected wheel bytes before target imports, then use a fresh interpreter."""

import argparse
import hashlib
import importlib.metadata as metadata
import json
import os
import stat
import subprocess
import sys
import tempfile
import types
from pathlib import Path
from urllib.parse import urldefrag
from zipfile import ZipFile

VERIFY_PIN = "a2a7e23413be0ab0ad1001d60085a2ff21eaa907"


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--wheel", required=True, type=Path)
    parser.add_argument("--source-archive", type=Path)
    return parser.parse_args()


def archive_identity(
    wheel: Path, own: metadata.Distribution, source_archive: Path | None = None
) -> tuple[dict, dict]:
    own_url = json.loads(own.read_text("direct_url.json") or "{}")
    assert not own_url.get("dir_info", {}).get("editable"), "editable install is not qualified"
    selected_archive = source_archive or wheel
    digest = hashlib.sha256(selected_archive.read_bytes()).hexdigest()
    archive_url, fragment = urldefrag(own_url.get("url", ""))
    assert archive_url == selected_archive.resolve().as_uri(), "installed archive URL differs"
    assert not fragment or fragment == f"sha256={digest}", "archive URL hash differs"
    archive_info = own_url.get("archive_info")
    assert isinstance(archive_info, dict), "installation is not recorded as an archive"
    hashes = archive_info.get("hashes", {})
    assert isinstance(hashes, dict), "archive hashes are malformed"
    if "sha256" in hashes:
        assert hashes["sha256"] == digest, "recorded archive SHA256 differs"
    legacy = archive_info.get("hash")
    legacy_present = isinstance(legacy, str) and legacy.startswith("sha256=")
    if legacy_present:
        assert legacy == f"sha256={digest}", "recorded archive SHA256 differs"
    return own_url, {
        "status": "EMITTED_AND_MATCHED" if "sha256" in hashes or legacy_present else "NOT_EMITTED",
        "hashesValue": hashes.get("sha256"),
        "legacyValue": legacy if legacy_present else None,
    }


def selected_wheel_checker(wheel: Path) -> types.ModuleType:
    """Load checker source from the selected artifact, never from installed caches."""
    namespace = "_probity_selected_wheel_identity"
    package = types.ModuleType(namespace)
    package.__path__ = []
    sys.modules[namespace] = package
    with ZipFile(wheel) as archive:
        for name in ("errors", "distribution"):
            source = archive.read("authority_effect/" + name + ".py")
            module = types.ModuleType(namespace + "." + name)
            module.__package__ = namespace
            sys.modules[module.__name__] = module
            exec(
                compile(source, str(wheel) + "!/authority_effect/" + name + ".py", "exec"),
                module.__dict__,
            )
    return sys.modules[namespace + ".distribution"]


def payload_before_import(wheel: Path, own: metadata.Distribution) -> dict:
    root = own.locate_file("")
    if not isinstance(root, Path):
        raise RuntimeError("installed distribution root is not a filesystem path")
    checker = selected_wheel_checker(wheel)
    return checker.installed_payload(wheel, own, root / "authority_effect/reader.py")


def fresh_runtime() -> bool:
    """Accept actual startup flags only with a private prefix still empty before imports."""
    if not sys.flags.isolated or not sys.dont_write_bytecode or not sys.pycache_prefix:
        return False
    prefix = Path(sys.pycache_prefix)
    info = prefix.lstat()
    targets = {"authority_effect", "probity_verify", "agent_evidence_vectors"}
    return (
        stat.S_ISDIR(info.st_mode)
        and stat.S_IMODE(info.st_mode) == 0o700
        and info.st_uid == os.geteuid()
        and not any(prefix.iterdir())
        and not any(name.split(".")[0] in targets for name in sys.modules)
    )


def qualification(args: argparse.Namespace, own_url: dict, archive: dict, payload: dict) -> int:
    assert fresh_runtime(), "fresh runtime not established before package imports"
    from authority_effect import reader
    from authority_effect.coverage_bridge import run_bridge
    from authority_effect.frequency_claims import run_supplied_controls
    from authority_effect.runner import run_controls

    assert sys.flags.isolated and sys.dont_write_bytecode and sys.pycache_prefix
    assert "site-packages" in Path(reader.__file__).parts, "reader imported from source checkout"
    assert (
        Path(reader.__file__).resolve()
        == (Path(payload["installedRoot"]) / "authority_effect/reader.py").resolve()
    ), "reader imported from another package location"
    assert Path(reader.__cached__).is_relative_to(Path(sys.pycache_prefix)), "legacy cache used"
    versions = {
        name: metadata.version(name)
        for name in ("probity-authority-effect-cases", "agent-evidence-vectors", "probity-verify")
    }
    assert versions["agent-evidence-vectors"] == "0.17.6", "Vectors pin differs"
    verify = metadata.distribution("probity-verify")
    verify_url = json.loads(verify.read_text("direct_url.json") or "{}")
    assert verify_url.get("vcs_info", {}).get("commit_id") == VERIFY_PIN, "Verify commit differs"
    args.output.mkdir(parents=True, exist_ok=True)
    controls = run_controls(args.output / "controls")
    bridge = run_bridge(args.output / "coverage-bridge")
    frequency = run_supplied_controls(args.output / "frequency-controls")
    report = {
        "schema": "probity.authority-effect-installed-qualification/v1",
        "versions": versions,
        "modulePath": reader.__file__,
        "pythonVersion": sys.version,
        "wheelSha256": hashlib.sha256(args.wheel.read_bytes()).hexdigest(),
        "selectedInstallArchive": {
            "path": str((args.source_archive or args.wheel).resolve()),
            "sha256": hashlib.sha256((args.source_archive or args.wheel).read_bytes()).hexdigest(),
            "kind": "source-archive" if args.source_archive else "wheel",
            "scope": "Source install bytes compared with separately rebuilt selected wheel"
            if args.source_archive
            else "Selected wheel install",
        },
        "ownSource": own_url,
        "archiveSha256Metadata": archive,
        "installedPayload": payload,
        "runtimeCacheProfile": {
            "actualPycachePrefix": sys.pycache_prefix,
            "isolated": bool(sys.flags.isolated),
            "dontWriteBytecode": sys.dont_write_bytecode,
            "readerCachedPath": reader.__cached__,
            "sourceBytesCheckedBeforeTargetImport": True,
            "scope": (
                "Selected wheel and baseline interpreter; "
                "arbitrary caller imports stay caller-owned"
            ),
        },
        "verifySource": verify_url,
        "controls": {key: controls[key] for key in ("passed", "total")},
        "coverageBridge": {
            key: bridge[key] for key in ("passed", "total", "vectorsExecuted", "vectorsFailures")
        },
        "frequencyControls": {key: frequency[key] for key in ("passed", "total")},
        "scope": "Same author and operator; installed-process checks of finite synthetic controls",
    }
    (args.output / "qualification.json").write_text(
        json.dumps(report, sort_keys=True, indent=2) + "\n"
    )
    print(json.dumps(report, sort_keys=True, indent=2))
    return int(
        controls["passed"] != controls["total"]
        or bridge["passed"] != bridge["total"]
        or bridge["vectorsExecuted"] != bridge["total"]
        or bool(bridge["vectorsFailures"])
        or frequency["passed"] != frequency["total"]
    )


def main() -> int:
    if sys.flags.optimize:
        raise RuntimeError("qualification requires enabled checks")
    args = arguments()
    own = metadata.distribution("probity-authority-effect-cases")
    own_url, archive = archive_identity(args.wheel, own, args.source_archive)
    payload = payload_before_import(args.wheel, own)
    if fresh_runtime():
        return qualification(args, own_url, archive, payload)
    root = own.locate_file("")
    assert isinstance(root, Path)
    with tempfile.TemporaryDirectory(prefix="authority-effect-qualification-") as temporary:
        cache_record = Path(temporary) / "fresh-import-profile.json"
        result = subprocess.run(
            [
                sys.executable,
                "-I",
                str(root / "authority_effect/isolated.py"),
                "--script",
                str(Path(__file__).resolve()),
                "--cache-record",
                str(cache_record),
                "--",
                *sys.argv[1:],
            ],
            check=False,
        )
        if cache_record.is_file() and args.output.is_dir():
            with (args.output / "fresh-import-profile.json").open("xb") as output:
                output.write(cache_record.read_bytes())
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
