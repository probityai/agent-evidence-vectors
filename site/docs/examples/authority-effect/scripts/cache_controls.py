"""Retain real installed bytecode, source-before-import and namespace controls."""

import argparse
import hashlib
import importlib.metadata as metadata
import importlib.util
import json
import marshal
import os
import py_compile
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path


def identity(path: Path) -> dict:
    data = path.read_bytes()
    return {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def run(name: str, argv: list[str], output: Path, *, environment: dict | None = None) -> dict:
    result = subprocess.run(argv, capture_output=True, timeout=240, env=environment, check=False)
    (output / (name + ".stdout")).write_bytes(result.stdout)
    (output / (name + ".stderr")).write_bytes(result.stderr)
    (output / (name + ".exit")).write_text(str(result.returncode) + "\n")
    return {
        "name": name,
        "argv": argv,
        "exit": result.returncode,
        "stdoutSha256": hashlib.sha256(result.stdout).hexdigest(),
        "stderrSha256": hashlib.sha256(result.stderr).hexdigest(),
    }


def protected_routes(
    root: Path, wheel: Path, name: str, output: Path, baseline: dict, archive_args: list[str]
) -> list[dict]:
    case = root / "authority_effect/fixtures/cases/matching-supplied-records.json"
    policy = root / "authority_effect/fixtures/policy.json"
    reader_args = ["read", str(case), "--policy", str(policy)]
    helper = root / "authority_effect/isolated.py"
    profile = output / (name + "-module.cache.json")
    routes = [
        (
            "module",
            [
                sys.executable,
                "-I",
                str(helper),
                "--module",
                "authority_effect.cli",
                "--cache-record",
                str(profile),
                "--",
                *reader_args,
            ],
        ),
        (
            "console",
            [str(Path(sys.executable).parent / "probity-authority-effect-cases"), *reader_args],
        ),
    ]
    api = output / (name + "-api.py")
    api.write_text(
        "import json\nfrom pathlib import Path\nfrom authority_effect import assess\n"
        f"print(json.dumps(assess(Path({str(case)!r}).read_bytes(), "
        f"Path({str(policy)!r}).read_bytes())))\n"
    )
    routes.append(
        (
            "api",
            [
                sys.executable,
                "-I",
                str(helper),
                "--script",
                str(api),
                "--cache-record",
                str(output / (name + "-api.cache.json")),
            ],
        )
    )
    rows = []
    for route, argv in routes:
        label = name + "-" + route
        row = run(label, argv, output)
        assert row["exit"] == 0 and not (output / (label + ".stderr")).read_bytes()
        assert json.loads((output / (label + ".stdout")).read_bytes()) == baseline
        if route in {"module", "api"}:
            profile = json.loads((output / (label + ".cache.json")).read_bytes())
            assert profile["beforeTargetImport"] and profile["privateEmptyPrefix"]
            assert profile["isolated"] and profile["dontWriteBytecode"]
            assert not profile["preloadedTargets"] and profile["prefixStillEmpty"]
            assert not Path(profile["actualPycachePrefix"]).exists()
        row["protectedRuntimeMatchesSource"] = True
        rows.append(row)
    qualification = output / (name + "-qualification")
    label = name + "-qualification"
    argv = [
        sys.executable,
        "-I",
        str(Path(__file__).with_name("qualify.py")),
        "--output",
        str(qualification),
        "--wheel",
        str(wheel),
        *archive_args,
    ]
    row = run(label, argv, output)
    assert row["exit"] == 0 and not (output / (label + ".stderr")).read_bytes()
    report = json.loads((qualification / "qualification.json").read_bytes())
    assert report["runtimeCacheProfile"]["sourceBytesCheckedBeforeTargetImport"]
    assert report["runtimeCacheProfile"]["actualPycachePrefix"]
    row["protectedRuntimeMatchesSource"] = True
    rows.append(row)
    return rows


def bytecode_controls(
    root: Path, wheel: Path, output: Path, baseline: dict, archive_args: list[str]
) -> list[dict]:
    rows = []
    for name in ("__init__", "reader", "cli"):
        source = root / "authority_effect" / (name + ".py")
        original_source = source.read_bytes()
        cache = source.parent / "__pycache__" / f"{name}.{sys.implementation.cache_tag}.pyc"
        original_cache = cache.read_bytes() if cache.exists() else None
        cache.parent.mkdir(exist_ok=True)
        try:
            for kind in ("legitimate", "mutant"):
                label = name + "-" + kind
                py_compile.compile(
                    str(source),
                    cfile=str(cache),
                    doraise=True,
                    invalidation_mode=py_compile.PycInvalidationMode.UNCHECKED_HASH,
                )
                if kind == "mutant":
                    code = compile(
                        f"raise RuntimeError('LEGACY_CACHE_MUTANT:{name}')\n", str(source), "exec"
                    )
                    cache.write_bytes(cache.read_bytes()[:16] + marshal.dumps(code))
                retained_cache = output / (label + ".pyc")
                retained_cache.write_bytes(cache.read_bytes())
                unprotected = run(
                    label + "-unprotected",
                    [sys.executable, "-I", "-c", f"import authority_effect.{name}"],
                    output,
                )
                expected_exit = 1 if kind == "mutant" else 0
                assert unprotected["exit"] == expected_exit
                if kind == "mutant":
                    assert (
                        f"LEGACY_CACHE_MUTANT:{name}".encode()
                        in (output / (label + "-unprotected.stderr")).read_bytes()
                    )
                unprotected["expectedExit"] = expected_exit
                unprotected["sourceIdentity"] = identity(source)
                unprotected["legacyCacheIdentity"] = identity(retained_cache)
                rows.append(unprotected)
                rows.extend(protected_routes(root, wheel, label, output, baseline, archive_args))
                assert source.read_bytes() == original_source
                assert cache.read_bytes() == retained_cache.read_bytes()
        finally:
            if original_cache is None:
                cache.unlink(missing_ok=True)
            else:
                cache.write_bytes(original_cache)
    return rows


def source_before_import_controls(
    root: Path, wheel: Path, output: Path, archive_args: list[str]
) -> list[dict]:
    rows = []
    for name in ("__init__", "reader", "cli"):
        source = root / "authority_effect" / (name + ".py")
        original = source.read_bytes()
        marker = output / (name + "-unwanted-execution")
        source.write_text(
            f"from pathlib import Path\nPath({str(marker)!r}).touch()\n"
            "raise RuntimeError('INSTALLED_SOURCE_MUTANT_EXECUTED')\n"
        )
        label = name + "-changed-source"
        try:
            refused = output / (label + "-refused")
            row = run(
                label,
                [
                    sys.executable,
                    "-I",
                    str(Path(__file__).with_name("qualify.py")),
                    "--output",
                    str(refused),
                    "--wheel",
                    str(wheel),
                    *archive_args,
                ],
                output,
            )
            stderr = (output / (label + ".stderr")).read_bytes()
            assert row["exit"] == 1 and b"installed payload bytes differ" in stderr
            assert b"INSTALLED_SOURCE_MUTANT_EXECUTED" not in stderr
            assert not marker.exists() and not refused.exists()
            row["sourceRefusedBeforeExecution"] = True
            rows.append(row)
        finally:
            source.write_bytes(original)
        assert source.read_bytes() == original
    return rows


def supplied_prefix_controls(
    root: Path, wheel: Path, output: Path, archive_args: list[str]
) -> list[dict]:
    """An actual -X prefix supplied by a caller is not proof that it was fresh."""
    rows = []
    source = root / "authority_effect/__init__.py"
    with tempfile.TemporaryDirectory(prefix="authority-effect-existing-cache-") as temporary:
        prefix = Path(temporary)
        previous = sys.pycache_prefix
        try:
            sys.pycache_prefix = str(prefix)
            cache = Path(importlib.util.cache_from_source(str(source)))
        finally:
            sys.pycache_prefix = previous
        cache.parent.mkdir(parents=True)
        for kind in ("legitimate", "mutant"):
            label = "supplied-prefix-" + kind
            py_compile.compile(
                str(source),
                cfile=str(cache),
                doraise=True,
                invalidation_mode=py_compile.PycInvalidationMode.UNCHECKED_HASH,
            )
            if kind == "mutant":
                code = compile(
                    "raise RuntimeError('SUPPLIED_PREFIX_MUTANT')\n", str(source), "exec"
                )
                cache.write_bytes(cache.read_bytes()[:16] + marshal.dumps(code))
            retained = output / (label + ".pyc")
            retained.write_bytes(cache.read_bytes())
            flags = [sys.executable, "-I", "-B", "-X", "pycache_prefix=" + str(prefix)]
            row = run(label + "-unprotected", [*flags, "-c", "import authority_effect"], output)
            assert row["exit"] == (1 if kind == "mutant" else 0)
            if kind == "mutant":
                assert (
                    b"SUPPLIED_PREFIX_MUTANT"
                    in (output / (label + "-unprotected.stderr")).read_bytes()
                )
            row["expectedExit"] = 1 if kind == "mutant" else 0
            row["legacyCacheIdentity"] = identity(retained)
            rows.append(row)
            qualification = output / (label + "-qualification")
            row = run(
                label + "-qualification",
                [
                    *flags,
                    str(Path(__file__).with_name("qualify.py")),
                    "--output",
                    str(qualification),
                    "--wheel",
                    str(wheel),
                    *archive_args,
                ],
                output,
            )
            assert (
                row["exit"] == 0 and not (output / (label + "-qualification.stderr")).read_bytes()
            )
            report = json.loads((qualification / "qualification.json").read_bytes())
            assert report["runtimeCacheProfile"]["actualPycachePrefix"] != str(prefix)
            assert report["runtimeCacheProfile"]["sourceBytesCheckedBeforeTargetImport"]
            assert cache.read_bytes() == retained.read_bytes()
            row["nonemptySuppliedPrefixReplacedBeforeTargetImport"] = True
            rows.append(row)
    return rows


def namespace_controls(root: Path, output: Path, baseline: dict) -> list[dict]:
    rows = []
    with tempfile.TemporaryDirectory(prefix="authority-effect-hostile-path-") as temporary:
        hostile = Path(temporary)
        marker = output / "sitecustomize-executed"
        (hostile / "sitecustomize.py").write_text(
            f"from pathlib import Path\nPath({str(marker)!r}).touch()\n"
        )
        (hostile / "authority_effect").mkdir()
        (hostile / "authority_effect/__init__.py").write_text(
            "raise RuntimeError('HOSTILE_NAMESPACE_EXECUTED')\n"
        )
        (output / "hostile-sitecustomize.py").write_bytes(
            (hostile / "sitecustomize.py").read_bytes()
        )
        (output / "hostile-authority-effect-init.py").write_bytes(
            (hostile / "authority_effect/__init__.py").read_bytes()
        )
        selected_environment = {
            "PYTHONPATH": str(hostile),
            "PYTHONPYCACHEPREFIX": str(hostile / "caller-cache"),
            "PYTHONOPTIMIZE": "2",
        }
        (output / "hostile-python-environment.json").write_text(
            json.dumps(selected_environment, indent=2) + "\n"
        )
        environment = dict(os.environ, **selected_environment)
        control = run(
            "hostile-path-positive-instrument",
            [sys.executable, "-c", "pass"],
            output,
            environment=environment,
        )
        assert control["exit"] == 0 and marker.is_file()
        marker.unlink()
        rows.append(control)
        case = root / "authority_effect/fixtures/cases/matching-supplied-records.json"
        policy = root / "authority_effect/fixtures/policy.json"
        label = "console-hostile-pythonpath"
        row = run(
            label,
            [
                str(Path(sys.executable).parent / "probity-authority-effect-cases"),
                "read",
                str(case),
                "--policy",
                str(policy),
            ],
            output,
            environment=environment,
        )
        assert row["exit"] == 0 and not (output / (label + ".stderr")).read_bytes()
        assert json.loads((output / (label + ".stdout")).read_bytes()) == baseline
        assert not marker.exists()
        row["pythonPathAndSitecustomizeIgnoredUnderIsolatedConsole"] = True
        rows.append(row)
    return rows


def optimized_qualification_controls(
    wheel: Path, output: Path, archive_args: list[str]
) -> list[dict]:
    rows = []
    for optimization in ("-O", "-OO"):
        label = "optimized-qualification-" + optimization.removeprefix("-")
        refused = output / (label + "-refused")
        row = run(
            label,
            [
                sys.executable,
                "-I",
                optimization,
                str(Path(__file__).with_name("qualify.py")),
                "--output",
                str(refused),
                "--wheel",
                str(wheel),
                *archive_args,
            ],
            output,
        )
        assert row["exit"] == 1
        assert (
            b"qualification requires enabled checks" in (output / (label + ".stderr")).read_bytes()
        )
        assert not refused.exists()
        row["expectedExit"] = 1
        row["disabledAssertionsRefusedBeforePackageImport"] = True
        rows.append(row)
    return rows


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--wheel", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--source-archive", type=Path)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    distribution = metadata.distribution("probity-authority-effect-cases")
    root = distribution.locate_file("")
    assert isinstance(root, Path)
    case = root / "authority_effect/fixtures/cases/matching-supplied-records.json"
    policy = root / "authority_effect/fixtures/policy.json"
    initial = run(
        "source-baseline",
        [
            str(Path(sys.executable).parent / "probity-authority-effect-cases"),
            "read",
            str(case),
            "--policy",
            str(policy),
        ],
        args.output,
    )
    assert initial["exit"] == 0 and not (args.output / "source-baseline.stderr").read_bytes()
    baseline = json.loads((args.output / "source-baseline.stdout").read_bytes())
    rows = [initial]
    archive_args = ["--source-archive", str(args.source_archive)] if args.source_archive else []
    rows.extend(bytecode_controls(root, args.wheel, args.output, baseline, archive_args))
    rows.extend(supplied_prefix_controls(root, args.wheel, args.output, archive_args))
    rows.extend(source_before_import_controls(root, args.wheel, args.output, archive_args))
    rows.extend(namespace_controls(root, args.output, baseline))
    rows.extend(optimized_qualification_controls(args.wheel, args.output, archive_args))
    report = {
        "schema": "probity.authority-effect-cache-controls/v1",
        "at": datetime.now(timezone.utc).isoformat(),
        "pythonVersion": sys.version,
        "rows": rows,
        "wheel": identity(args.wheel),
        "installedRoot": str(root),
        "scope": (
            "Actual installed local package controls; trusted selected wheel and interpreter; "
            "no arbitrary caller or sandbox guarantee"
        ),
    }
    (args.output / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"controls": len(rows), "report": str(args.output / "result.json")}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
