#!/usr/bin/env python3
"""Check the source license copy and the license in built Python archives."""

import argparse
import sys
import tarfile
import zipfile
from email.parser import BytesParser
from pathlib import Path


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def source_license(root: Path) -> bytes:
    """The repository LICENSE is the source; python/LICENSE is a build copy."""
    expected = (root / "LICENSE").read_bytes()
    require(
        (root / "python/LICENSE").read_bytes() == expected,
        "python/LICENSE differs from repository LICENSE; copy the root license",
    )
    return expected


def check_metadata(data: bytes) -> None:
    metadata = BytesParser().parsebytes(data, headersonly=True)
    require(
        metadata.get_all("License-Expression") == ["Apache-2.0"],
        "package metadata must declare License-Expression: Apache-2.0",
    )
    require(
        metadata.get_all("License-File") == ["LICENSE"],
        "package metadata must declare License-File: LICENSE",
    )


def check_wheel(path: Path, expected: bytes) -> None:
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        require(len(names) == len(set(names)), "wheel has duplicate members")
        metadata = [name for name in names if name.endswith(".dist-info/METADATA")]
        require(len(metadata) == 1, "wheel must contain one distribution metadata file")
        check_metadata(archive.read(metadata[0]))
        license_path = metadata[0].rsplit("/", 1)[0] + "/licenses/LICENSE"
        require(archive.read(license_path) == expected, "wheel license differs from repository LICENSE")


def check_sdist(path: Path, expected: bytes) -> None:
    with tarfile.open(path, "r:gz") as archive:
        names = archive.getnames()
        require(len(names) == len(set(names)), "source archive has duplicate members")
        metadata = [name for name in names if name.endswith("/PKG-INFO")]
        require(len(metadata) == 1, "source archive must contain one package metadata file")
        root = metadata[0].rsplit("/", 1)[0]
        for name in [metadata[0], root + "/LICENSE"]:
            require(archive.getmember(name).isfile(), "source license and metadata must be regular files")
        with archive.extractfile(metadata[0]) as stream:
            check_metadata(stream.read())
        with archive.extractfile(root + "/LICENSE") as stream:
            require(stream.read() == expected, "source archive license differs from repository LICENSE")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dist", type=Path, help="also check one built wheel and source archive")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    try:
        expected = source_license(root)
        if args.dist is not None:
            wheels = list(args.dist.glob("*.whl"))
            sdists = list(args.dist.glob("*.tar.gz"))
            require(len(wheels) == 1 and len(sdists) == 1, "dist must contain one wheel and one source archive")
            check_wheel(wheels[0], expected)
            check_sdist(sdists[0], expected)
    except (OSError, ValueError, KeyError, zipfile.BadZipFile, tarfile.TarError) as error:
        print(f"FAIL Python package license: {error}", file=sys.stderr)
        return 1
    print("PASS Python package license matches repository LICENSE")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
