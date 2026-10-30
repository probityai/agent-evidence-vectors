"""Published run records carry no absolute local path.

Literal roots are built from parts so this file holds none for the repository scans.
"""

import base64
import gzip
import importlib.util
import io
import re
import subprocess
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
_SPEC = importlib.util.spec_from_file_location(
    "record_paths", ROOT / "scripts" / "record_paths.py")
record_paths = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(record_paths)

S = "/"
REFUSED = [
    S + "home" + S + "someone" + S + "work",
    S + "Users" + S + "someone" + S + "x",
    "C:" + "\\" + "Users" + "\\" + "someone",
    "~" + S + "Documents",
    S + "mnt" + S + "data",
    S + "blue" + S + "group" + S + "u",
    S + "root" + S + "case",
]


@pytest.mark.parametrize("path", REFUSED)
def test_every_local_root_is_found(path: str) -> None:
    assert record_paths.find_local_path(f"run at {path} done") is not None


@pytest.mark.parametrize(
    "text",
    ["pages/x/report.json", "../.build/result", "https://example.invalid/home/page",
     "see the foo/tmp/bar file", "a~/b"],
)
def test_repo_relative_paths_and_urls_pass(text: str) -> None:
    assert record_paths.find_local_path(text) is None


def test_ci_homes_pass_and_a_person_home_does_not() -> None:
    assert record_paths.find_local_path(S + "home" + S + "runner" + S + "w") is None
    assert record_paths.find_local_path(S + "home" + S + "gate" + S + "w") is None
    assert record_paths.find_local_path(S + "home" + S + "alice" + S + "w") is not None


def test_scratch_is_found_unless_allowed() -> None:
    scratch = S + "tmp" + S + "x"
    assert record_paths.find_local_path(scratch) is not None
    assert record_paths.find_local_path(scratch, allow_scratch=True) is None


def test_relativize_rewrites_under_the_root_and_refuses_outside(tmp_path: Path) -> None:
    assert record_paths.relativize(tmp_path / "a" / "b.json", tmp_path) == "a/b.json"
    with pytest.raises(ValueError, match="no repo-relative form"):
        record_paths.relativize(tmp_path.parent / "elsewhere", tmp_path)


# Recorded CI logs and frozen reports keep the scratch directories their runs used,
# so the scan allows /tmp. Every other root is refused in every published record.
RECORD_SUFFIXES = (".diff", ".json", ".jsonl", ".log", ".txt", ".stderr", ".stdout", ".xml")


def _tracked(*pathspec: str) -> list[Path]:
    out = subprocess.run(
        ["git", "ls-files", "-z", *pathspec], cwd=ROOT, capture_output=True, check=True
    ).stdout.decode()
    return [ROOT / n for n in out.split("\0") if n]


# These files define the path patterns themselves, so they must spell the roots.
PATTERN_DEFINERS = {
    "scripts/record_paths.py",
    "tests/test_record_paths.py",
    "packages/admission/scripts/host-allowlist-gate.py",
    "packages/admission/scripts/pre-push-identity-scan.py",
    "packages/vocabulary/scripts/pre-push-identity-scan.py",
}
_B64 = re.compile(rb"[A-Za-z0-9+/_-]{24,}={0,2}")


def _decoded_views(data: bytes, name: str, depth: int = 0):
    """Yield (name, text) for ``data`` and for every archive member or encoded field in it."""
    binary = data[:2] in (b"\x1f\x8b", b"PK")
    if not binary:
        yield name, data.decode("utf-8", errors="replace")
    if depth > 3:
        return
    if data[:2] == b"\x1f\x8b":
        try:
            yield from _decoded_views(gzip.decompress(data), name + "!gz", depth + 1)
        except (OSError, EOFError):
            pass
    if data[:2] == b"PK":
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as z:
                for member in z.namelist():
                    if member.endswith(RECORD_SUFFIXES):
                        yield from _decoded_views(z.read(member), f"{name}!{member}", depth + 1)
        except zipfile.BadZipFile:
            pass
    for m in ([] if binary else _B64.finditer(data)):
        raw = m.group()
        try:
            decoded = base64.b64decode(raw.replace(b"-", b"+").replace(b"_", b"/")
                                       + b"=" * (-len(raw) % 4))
        except ValueError:
            continue
        if len(decoded) > 8 and (decoded[:2] in (b"\x1f\x8b", b"PK") or decoded.isascii()):
            yield from _decoded_views(decoded, name + "!b64", depth + 1)


def _leaks(paths: list[Path], *, decode: bool) -> list[str]:
    leaks = []
    for path in paths:
        rel = path.relative_to(ROOT).as_posix()
        if rel in PATTERN_DEFINERS or not path.is_file():
            continue
        data = path.read_bytes()
        if decode and b"\0" in data[:8192] and data[:2] not in (b"PK", b"\x1f\x8b"):
            continue
        views = _decoded_views(data, rel) if decode else [(rel, data.decode("utf-8", "replace"))]
        for name, text in views:
            found = (record_paths.find_home_path(text) if decode
                     else record_paths.find_local_path(text, allow_scratch=True))
            if found is not None:
                leaks.append(f"{name}: {found!r}")
    return leaks


def test_no_tracked_file_or_encoded_field_carries_an_absolute_local_path() -> None:
    """Every tracked file, plus zip members, gzip streams and base64 fields inside them."""
    leaks = _leaks(_tracked(), decode=True)
    assert not leaks, "\n".join(leaks)


def test_the_scan_decodes_encoded_fields(tmp_path: Path) -> None:
    secret = (S + "home" + S + "alice" + S + "w").encode()
    payload = base64.b64encode(gzip.compress(secret * 3)).decode()
    names = [n for n, t in _decoded_views(f'{{"x": "{payload}"}}'.encode(), "r.json")
             if record_paths.find_home_path(t) is not None]
    assert names, "an encoded home path went unseen"
