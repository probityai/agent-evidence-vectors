"""Write and check INPUTS.json: source, per-file SHA-256 and trust-key pins.

``python pins.py`` rewrites INPUTS.json from the files on disk. ``check_pins`` is what
every run calls first: each pinned file must hash to its pin, and no unpinned file may
sit among the inputs. A failure is an InputError, which the runner turns into exit 2.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import Any

from strict_json import load_json, read_bounded, refuse

HERE = Path(__file__).resolve().parent
PINS = HERE / "INPUTS.json"
INPUT_ROOTS = ("fixtures", "cases")
FIXTURE_DIR = "fixtures/aae-v1.4.0"

SOURCE: dict[str, str] = {
    "repository": "https://github.com/MoltyCel/aae-conformance-vectors",
    "tag": "v1.4.0",
    "commit": "531f880155ea1ce993a7ca74137b12c255d5b2ee",
    "set_version": "1.4.0",
    "specification": "draft-kroehl-agentic-trust-aae-02",
    "license": "Apache-2.0",
    "copyright": "2026 CryptoKRI GmbH, Zurich (MolTrust)",
    "author": "Lars Kroehl (MoltyCel)",
    "attribution": "The 26 enforce vectors, LICENSE and NOTICE are retained byte for byte from "
    "the tag; this package changes none of them.",
}

TRUST_KEYS: list[dict[str, Any]] = [
    {
        "did": "did:web:example.com:registry",
        "public_key": "9d53a7a4431e299b0ceb950ccbd5bd6f4845cdd9c7bd38e1c9e4e26490f8f90e",
        "source_path": "testkeys/issuer-test-key-1.json",
        "source_sha256": "0d60eaa2d7e9c59664667f9fe36d236093a395fccd10273da7b761fa5c3306ca",
        "named_by": ["aae-enforce-vector-22", "aae-enforce-vector-23", "aae-enforce-vector-24",
                     "aae-enforce-vector-25", "aae-enforce-vector-26"],
        "note": "Upstream test key, public by design (NOTICE); never a production key.",
    }
]
UNTRUSTED_KEYS: list[dict[str, Any]] = [
    {
        "did": "did:web:example.com:stranger",
        "public_key": "03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8",
        "source_path": "tools/build_enforce_vectors.py",
        "source_sha256": "f895a47cbe3c86e37036e2b51646d7feaa42f7f456077d3f7c163e3953a3b19e",
        "note": "Signs vector 23. Named in no mandate and absent from the pin set; its "
        "signature verifies under this key and is still rejected.",
    }
]
EVIDENCE_KEYS: list[dict[str, Any]] = [
    {
        "role": "observed-effect observer",
        "keyid": "f3cb9b6750737ef6789a72b71d8305f2",
        "public_key": "4f2a59edc8367deb40047ce83ee7f5ce711a57d93abbda9d1ce8588c56a3ce88",
        "source_path": "vectors-observed-effect/gen_vectors.py",
        "note": "This repository's fixed observed-effect test observer key (seed 0x00..11). "
        "It signs the case evidence records; it is a test key, never a production key.",
    }
]
KEY_RULE = (
    "A ratification is evaluated only when every authority key its mandate names equals "
    "the pinned key for that DID. An evidence record is checked only under the pinned "
    "observer key. Any other key is refused before evaluation, and the run exits 2."
)


def sha256(data: bytes) -> str:
    """Lowercase hex SHA-256."""
    return hashlib.sha256(data).hexdigest()


def input_files(root: Path = HERE) -> list[str]:
    """Every file under the input roots, as sorted root-relative POSIX paths."""
    found = [path for base in INPUT_ROOTS for path in (root / base).rglob("*") if path.is_file()]
    return sorted(path.relative_to(root).as_posix() for path in found)


def file_entry(relative: str, root: Path = HERE) -> dict[str, Any]:
    """One pin: path, role, byte count and digest, plus the upstream path for fixtures."""
    data = (root / relative).read_bytes()
    entry: dict[str, Any] = {"path": relative, "sha256": sha256(data), "bytes": len(data)}
    if relative.startswith(FIXTURE_DIR + "/"):
        name = relative.removeprefix(FIXTURE_DIR + "/")
        upstream = {"LICENSE.upstream": "LICENSE", "NOTICE.upstream": "NOTICE"}
        entry["role"] = "upstream"
        entry["source_path"] = upstream.get(name, f"vectors/enforce/{name}")
    else:
        entry["role"] = "case"
    return entry


def build(root: Path = HERE) -> dict[str, Any]:
    """The full INPUTS.json document for the input tree under ``root``."""
    return {
        "source": SOURCE,
        "files": [file_entry(relative, root) for relative in input_files(root)],
        "trust_keys": TRUST_KEYS,
        "untrusted_keys_seen": UNTRUSTED_KEYS,
        "evidence_keys": EVIDENCE_KEYS,
        "key_rule": KEY_RULE,
    }


def render(document: dict[str, Any]) -> str:
    """Stable, ASCII-only serialization."""
    return json.dumps(document, indent=2, ensure_ascii=True) + "\n"


def check_pins(root: Path = HERE) -> dict[str, Any]:
    """Verify every pinned file and refuse unpinned inputs; return the pin document."""
    document = load_json(read_bounded(root / "INPUTS.json"))
    files = document.get("files")
    if not isinstance(files, list) or document.get("source") != SOURCE:
        refuse("INPUTS.json source or file list differs from the declared pins")
    listed: set[str] = set()
    for item in files:
        if not isinstance(item, dict) or not isinstance(item.get("path"), str):
            refuse("INPUTS.json carries a malformed file entry")
        if not item["path"].startswith(tuple(f"{base}/" for base in INPUT_ROOTS)) or (
            ".." in item["path"].split("/")
        ):
            refuse("INPUTS.json pins a path outside the input tree")
        path = root / item["path"]
        if sha256(read_bounded(path)) != item.get("sha256"):
            refuse("an input file differs from its SHA-256 pin")
        listed.add(item["path"])
    if set(input_files(root)) != listed:
        refuse("the input tree holds a file the pins do not list, or lacks a pinned one")
    if document.get("trust_keys") != TRUST_KEYS or document.get("evidence_keys") != EVIDENCE_KEYS:
        refuse("INPUTS.json key pins differ from the declared pins")
    return document


def trust_pins() -> dict[str, str]:
    """DID to pinned public key."""
    return {str(entry["did"]): str(entry["public_key"]) for entry in TRUST_KEYS}


if __name__ == "__main__":
    PINS.write_text(render(build()), encoding="ascii")
    sys.exit(0)
