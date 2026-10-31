"""Bind installed package and metadata bytes to one selected wheel."""

import hashlib
import stat
import sys
from importlib.metadata import Distribution
from pathlib import Path, PurePosixPath
from zipfile import BadZipFile, ZipFile

from .errors import InputError

PACKAGE = "authority_effect"
# uv 0.12.8 writes uv_cache.json in write_installer_metadata. These exact names
# permit installer additions; every selected wheel member still has its bytes
# compared below, except the installer-rewritten RECORD.
INSTALLER_METADATA = {
    "RECORD",
    "INSTALLER",
    "REQUESTED",
    "direct_url.json",
    "uv_cache.json",
    "uv_build.json",
}


def _wheel_metadata_prefix(names: list[str]) -> str:
    prefixes = {
        parts[0] + "/"
        for name in names
        if len(parts := PurePosixPath(name).parts) == 2
        and parts[1] == "METADATA"
        and parts[0].startswith("probity_authority_effect_cases-")
        and parts[0].endswith(".dist-info")
    }
    if len(prefixes) != 1:
        raise InputError("selected wheel lacks one required package metadata directory")
    return prefixes.pop()


def _wheel_payload(wheel: Path) -> tuple[str, dict[str, bytes]]:
    payload: dict[str, bytes] = {}
    try:
        with ZipFile(wheel) as archive:
            # Installed METADATA may be missing or malformed. Select its exact
            # directory from the trusted wheel before any installed parser runs.
            metadata_prefix = _wheel_metadata_prefix(archive.namelist())
            launcher = (
                metadata_prefix.removesuffix(".dist-info/")
                + ".data/scripts/probity-authority-effect-cases"
            )
            for item in archive.infolist():
                if stat.S_ISLNK(item.external_attr >> 16):
                    raise InputError("selected wheel contains a symlink member")
                if item.is_dir():
                    continue
                name = item.filename
                path = PurePosixPath(name)
                if (
                    path.is_absolute()
                    or ".." in path.parts
                    or "\\" in name
                    or str(path) != name
                    or name in payload
                    or not (name.startswith((PACKAGE + "/", metadata_prefix)) or name == launcher)
                ):
                    raise InputError("wheel has an unsafe, duplicate or unsupported member")
                payload[name] = archive.read(item)
    except BadZipFile as exc:
        raise InputError("selected wheel does not parse") from exc
    required = {
        PACKAGE + "/reader.py",
        metadata_prefix + "METADATA",
        metadata_prefix + "WHEEL",
        metadata_prefix + "RECORD",
        launcher,
    }
    if not required <= payload.keys():
        raise InputError("selected wheel lacks the required package or metadata")
    return metadata_prefix, payload


def _installed_names(root: Path, prefix: str, *, bytecode: bool = False) -> set[str]:
    names = set()
    directory = root / prefix
    if directory.is_symlink():
        raise InputError("installed payload directory is a symlink")
    for path in directory.rglob("*"):
        if path.is_symlink():
            raise InputError("installed payload contains a symlink")
        if not path.is_file():
            continue
        relative = path.relative_to(root)
        if bytecode and "__pycache__" in relative.parts and path.suffix == ".pyc":
            continue
        names.add(relative.as_posix())
    return names


def installed_payload(
    wheel: Path,
    distribution: Distribution,
    module_file: Path,
    *,
    launcher_file: Path | None = None,
) -> dict:
    """Reject changed, missing or additional payload independently of installation metadata."""
    metadata_prefix, payload = _wheel_payload(wheel)
    located_root = distribution.locate_file("")
    if not isinstance(located_root, Path):
        raise InputError("installed distribution root is not a filesystem path")
    root = located_root.resolve()
    if module_file.resolve() != (root / PACKAGE / "reader.py").resolve():
        raise InputError("reader imported from another package location")
    expected_package = {name for name in payload if name.startswith(PACKAGE + "/")}
    if _installed_names(root, PACKAGE, bytecode=True) != expected_package:
        raise InputError("installed package file population differs from selected wheel")
    expected_metadata = {name for name in payload if name.startswith(metadata_prefix)}
    installer_metadata = {metadata_prefix + name for name in INSTALLER_METADATA}
    actual_metadata = _installed_names(root, metadata_prefix)
    if (
        not expected_metadata <= actual_metadata
        or actual_metadata - expected_metadata - installer_metadata
    ):
        raise InputError("installed metadata file population differs from selected wheel")
    rows = []
    for name, content in sorted(payload.items()):
        if name == metadata_prefix + "RECORD":
            continue
        installed = (
            launcher_file or Path(sys.executable).parent / "probity-authority-effect-cases"
            if ".data/scripts/" in name
            else root / name
        )
        if not installed.is_file() or installed.is_symlink() or installed.read_bytes() != content:
            raise InputError(f"installed payload bytes differ: {name}")
        rows.append(
            {"path": name, "bytes": len(content), "sha256": hashlib.sha256(content).hexdigest()}
        )
    return {
        "wheelSha256": hashlib.sha256(wheel.read_bytes()).hexdigest(),
        "installedRoot": str(root),
        "files": rows,
        "installerGeneratedMetadata": [
            {
                "path": name,
                "bytes": (root / name).stat().st_size,
                "sha256": hashlib.sha256((root / name).read_bytes()).hexdigest(),
            }
            for name in sorted(actual_metadata - expected_metadata)
        ],
        "scope": (
            "Complete wheel package, metadata and console-script payload "
            "except installer-rewritten RECORD; "
            "generated bytecode is excluded; permitted installer additions are recorded separately"
        ),
    }
