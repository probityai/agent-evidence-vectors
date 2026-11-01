"""Parse the frontmatter of a SKILL.md: the reference reader for ``skill-frontmatter-parse/v1``.

The Agent Skills format says which fields a skill declares and not which octets are the
declaration, so clients disagree about where a block closes, what a document-end line does and
what a repeated key means. ``vectors-skill-frontmatter/SPEC.md`` proposes eleven steps that give
every file one answer. This module is those steps, using only the standard library.

Steps 1 to 10 are a line scan. Step 11 needs a YAML processor, so it is an optional hook:
``parse`` takes ``yaml_check`` and skips the step without one. The two corpus cases that exercise
step 11 are marked ``needsYaml`` and are run only when a processor is available.

The external-verifier contract: ``<verifier> <case-dir>/SKILL.md --json`` prints one JSON object
carrying ``outcome`` (``ok`` or ``error``) and, for ``ok``, ``keys`` and ``body``, or for
``error``, ``code`` and ``line`` (``null`` when the refusal concerns the file as a whole). It
exits 0 whenever it produced an answer and 2 on a file it could not read. A verifier without a
YAML processor answers only the cases not marked ``needsYaml``; set
``AEV_SKILL_YAML_PROCESSOR=1`` to include them when the verifier has one.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shlex
import subprocess
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any

SUITE = "skill-frontmatter-parse/v1"
MAX_FILE_OCTETS = 1024 * 1024
MAX_FRONTMATTER_OCTETS = 64 * 1024

_BOM = b"\xef\xbb\xbf"
_LINE_TERMINATOR = re.compile(r"\r\n|\n|\r")
_BLANK_OR_COMMENT = re.compile(r"^[ \t]*(?:#.*)?$")
_DOCUMENT_MARKER = re.compile(r"^(?:\.\.\.|---)(?:[ \t]|$)")
_KEY_COLON = re.compile(r":(?=[ \t]|$)")
_COMMENT_START = re.compile(r"[ \t]#")
_SEQUENCE_ENTRY = re.compile(r"^-(?:[ \t]|$)")
_PLAIN_FORBIDDEN_FIRST = frozenset("#&*!|>'\"%@`[]{},")
_DOUBLE_ESCAPES: Mapping[str, str] = MappingProxyType(
    {"\\": "\\", '"': '"', "/": "/", "n": "\n", "t": "\t", "r": "\r", "0": "\0", " ": " "}
)


@dataclass(frozen=True)
class Accepted:
    """A file the steps accepted: its top-level keys in order and its body."""

    keys: tuple[str, ...]
    body: str


@dataclass(frozen=True)
class Refused:
    """A file the steps refused: the code and the 1-based line, or ``None`` for the whole file."""

    code: str
    line: int | None = None


YamlCheck = Callable[[str], bool]


def _lines(text: str) -> tuple[list[str], list[int]]:
    """Line contents without terminators, and the offset just past each terminator."""
    contents: list[str] = []
    ends: list[int] = []
    position = 0
    for match in _LINE_TERMINATOR.finditer(text):
        contents.append(text[position : match.start()])
        ends.append(match.end())
        position = match.end()
    if position < len(text):
        contents.append(text[position:])
        ends.append(len(text))
    return contents, ends


def _trim(line: str) -> str:
    return line.rstrip(" \t")


def _has_control_character(block: str) -> bool:
    return any((ord(c) < 0x20 and c not in "\t\r\n") or ord(c) == 0x7F for c in block)


def _decode_double_quoted(raw: str) -> str | None:
    out: list[str] = []
    index = 0
    while index < len(raw):
        char = raw[index]
        if char != "\\":
            out.append(char)
            index += 1
            continue
        if index + 1 >= len(raw) or raw[index + 1] not in _DOUBLE_ESCAPES:
            return None
        out.append(_DOUBLE_ESCAPES[raw[index + 1]])
        index += 2
    return "".join(out)


def _closing_quote(line: str) -> int | None:
    """Index of the quote that closes the scalar opening ``line``, or ``None``."""
    quote = line[0]
    index = 1
    while index < len(line):
        if quote == '"' and line[index] == "\\":
            index += 2
        elif line[index] != quote:
            index += 1
        elif quote == "'" and line[index + 1 : index + 2] == "'":
            index += 2
        else:
            return index
    return None


def _quoted_key(line: str) -> tuple[str, str] | None:
    end = _closing_quote(line)
    if end is None:
        return None
    rest = line[end + 1 :].lstrip(" \t")
    if not rest.startswith(":") or (len(rest) > 1 and rest[1] not in " \t"):
        return None
    raw = line[1:end]
    key = raw.replace("''", "'") if line[0] == "'" else _decode_double_quoted(raw)
    return None if key is None else (key, rest[1:])


def _plain_key(line: str) -> tuple[str, str] | None:
    if line[0] in _PLAIN_FORBIDDEN_FIRST or (line[0] == "?" and line[1:2] in ("", " ", "\t")):
        return None
    match = _KEY_COLON.search(line)
    if match is None:
        return None
    key = line[: match.start()].rstrip(" \t")
    if not key or _COMMENT_START.search(key):
        return None
    return key, line[match.end() :]


def _entry(line: str) -> tuple[str, str] | None:
    """``(key, text after the colon)`` for a column-0 ``key: value`` line."""
    return _quoted_key(line) if line[0] in "'\"" else _plain_key(line)


def _scan_entries(block_lines: list[str], first_line: int) -> tuple[str, ...] | Refused:
    """Steps 9 and 10 over the block's lines; ``first_line`` numbers the first one."""
    keys: list[str] = []
    seen: set[str] = set()
    open_for_sequence = False
    for number, line in enumerate(block_lines, start=first_line):
        if _BLANK_OR_COMMENT.match(line):
            continue
        if line[0] in " \t":
            if not keys:
                return Refused("root-not-block-mapping", number)
            open_for_sequence = False
            continue
        if _SEQUENCE_ENTRY.match(line) and open_for_sequence:
            continue
        parsed = _entry(line)
        if parsed is None:
            return Refused("invalid-entry" if keys else "root-not-block-mapping", number)
        key, rest = parsed
        if key in seen:
            return Refused("duplicate-key", number)
        seen.add(key)
        keys.append(key)
        open_for_sequence = _BLANK_OR_COMMENT.match(rest) is not None
    return tuple(keys)


def _document_marker(block_lines: list[str], first_line: int) -> Refused | None:
    """Step 7, found before any structural verdict so an earlier bad line cannot hide it."""
    for number, line in enumerate(block_lines, start=first_line):
        if _DOCUMENT_MARKER.match(line):
            return Refused(
                "document-end-marker" if line.startswith("...") else "document-start-marker",
                number,
            )
    return None


def _frame(data: bytes) -> tuple[str, list[str], list[int], int] | Refused:
    """Steps 1 to 4: the decoded text, its lines, their ends and the closing line's index."""
    if len(data) > MAX_FILE_OCTETS:
        return Refused("file-too-large")
    if data.startswith(_BOM):
        return Refused("byte-order-mark", 1)
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return Refused("invalid-utf8")
    lines, ends = _lines(text)
    if not lines or _trim(lines[0]) != "---":
        return Refused("no-opening-delimiter", 1)
    closing = next((i for i in range(1, len(lines)) if _trim(lines[i]) == "---"), None)
    if closing is None:
        return Refused("unterminated-frontmatter", 1)
    return text, lines, ends, closing


def _check_block(block: str, block_lines: list[str]) -> tuple[str, ...] | Refused:
    """Steps 5 to 10 over the frontmatter block."""
    if len(block.encode("utf-8")) > MAX_FRONTMATTER_OCTETS:
        return Refused("frontmatter-too-large", 2)
    if _has_control_character(block):
        return Refused("control-character")
    marker = _document_marker(block_lines, 2)
    if marker is not None:
        return marker
    if all(_BLANK_OR_COMMENT.match(line) for line in block_lines):
        return Refused("frontmatter-empty", 2)
    return _scan_entries(block_lines, 2)


def parse(data: bytes, *, yaml_check: YamlCheck | None = None) -> Accepted | Refused:
    """Apply the steps to the octets of a SKILL.md; never raises.

    Returns the accepted file or the first refusal in step order. ``yaml_check`` is the step 11
    processor: it takes the block and returns whether it loads as one YAML document.
    """
    framed = _frame(data)
    if isinstance(framed, Refused):
        return framed
    text, lines, ends, closing = framed
    block = text[ends[0] : ends[closing - 1]] if closing > 1 else ""
    keys = _check_block(block, lines[1:closing])
    if isinstance(keys, Refused):
        return keys
    if yaml_check is not None and not yaml_check(block):
        return Refused("yaml-syntax-error")
    return Accepted(keys, text[ends[closing] :])


def yaml_processor() -> YamlCheck | None:
    """PyYAML as the step 11 processor when it is installed, else ``None``."""
    try:
        import yaml
    except ImportError:
        return None

    def check(block: str) -> bool:
        try:
            yaml.safe_load(block)
        except yaml.YAMLError:
            return False
        return True

    return check


def answer(result: Accepted | Refused) -> dict[str, Any]:
    """The object a verifier prints for one file."""
    if isinstance(result, Refused):
        return {"outcome": "error", "code": result.code, "line": result.line}
    return {"outcome": "ok", "keys": list(result.keys), "body": result.body}


def verify(path: Path, yaml_check: YamlCheck | None = None) -> dict[str, Any]:
    """Read one SKILL.md and answer it with the reference steps."""
    return answer(parse(path.read_bytes(), yaml_check=yaml_check))


# -- the corpus ----------------------------------------------------------------

_HERE = Path(__file__).resolve().parent
ROOT = (
    _HERE / "corpora" / "vectors-skill-frontmatter"
    if (_HERE / "corpora").exists()
    else _HERE.parents[1] / "vectors-skill-frontmatter"
)


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()


def _fixture_error(directory: Path, entry: dict[str, Any]) -> str | None:
    files = entry["files"]
    if {path.name for path in directory.iterdir() if path.is_file()} != set(files):
        return "file set changed"
    if any(_sha((directory / name).read_bytes()) != digest for name, digest in files.items()):
        return "fixture digest mismatch"
    return None


def _validated_entries(root: Path) -> tuple[list[dict[str, Any]], str | None]:
    manifest = json.loads((root / "MANIFEST.json").read_text(encoding="utf-8"))
    entries = manifest["vectors"]
    if _sha(_json(entries)) != manifest["corpusDigest"]:
        return [], "manifest digest mismatch"
    if manifest.get("suite") != SUITE:
        return [], "unexpected suite"
    if not entries or len({entry["id"] for entry in entries}) != len(entries):
        return [], "empty or duplicate vector identifiers"
    if any(entry.get("path") != f"cases/{entry['id']}" for entry in entries):
        return [], "case path does not match identifier"
    if {p.name for p in (root / "cases").iterdir() if p.is_dir()} != {e["id"] for e in entries}:
        return [], "case directories do not match manifest"
    return entries, None


def _external_answer(command: list[str], skill_path: Path) -> tuple[bool, dict[str, Any] | str]:
    try:
        result = subprocess.run(
            [*command, str(skill_path), "--json"],
            capture_output=True,
            text=True,
            timeout=90,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, f"verifier did not run: {exc}"
    try:
        observed = json.loads(result.stdout)
        if not isinstance(observed, dict):
            raise TypeError
    except (ValueError, TypeError):
        return True, f"verifier returned no JSON object (exit {result.returncode})"
    if result.returncode:
        return True, f"exit {result.returncode} for an answered case"
    return True, observed


def _disagreement(expected: dict[str, Any], observed: dict[str, Any]) -> bool:
    return any(observed.get(key, _MISSING) != value for key, value in expected.items())


_MISSING = object()


def check(
    verifier: str | list[str] | None = None,
    root: Path = ROOT,
    *,
    yaml_check: YamlCheck | None = None,
    external_yaml: bool = False,
) -> tuple[int, int, list[str]]:
    """Check every case through the named verifier or the reference reader.

    Returns ``(answered, not_applicable, disagreements)``. A case marked ``needsYaml`` is not
    applicable when the reader has no YAML processor (``yaml_check`` is ``None``) or, for an
    external verifier, when ``external_yaml`` is false. It is counted, never skipped silently.
    """
    try:
        entries, manifest_error = _validated_entries(root)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        return 0, 0, [f"invalid corpus: {exc}"]
    if manifest_error:
        return 0, 0, [manifest_error]
    command = shlex.split(verifier) if isinstance(verifier, str) else verifier
    if command is not None and not command:
        return 0, 0, ["verifier command is empty"]
    errors: list[str] = []
    answered = not_applicable = 0
    for entry in entries:
        name, directory = entry["id"], root / entry["path"]
        fixture_error = _fixture_error(directory, entry)
        if fixture_error:
            errors.append(f"{name}: {fixture_error}")
            continue
        has_processor = yaml_check is not None if command is None else external_yaml
        if entry.get("needsYaml") and not has_processor:
            not_applicable += 1
            continue
        observed: dict[str, Any] | str
        if command is None:
            ran, observed = True, verify(directory / "SKILL.md", yaml_check)
        else:
            ran, observed = _external_answer(command, directory / "SKILL.md")
        answered += int(ran)
        if isinstance(observed, str):
            errors.append(f"{name}: {observed}")
        elif _disagreement(entry["expected"], observed):
            errors.append(f"{name}: expected {entry['expected']}, got {observed}")
    return answered, not_applicable, errors


def run(root: str, verifier: list[str] | None, report_path: str, rail_note: str) -> int:
    """Judge the corpus and write the report the package's other suites write."""
    directory = Path(root)
    answered, not_applicable, errors = check(
        verifier,
        directory,
        yaml_check=yaml_processor(),
        external_yaml=os.environ.get("AEV_SKILL_YAML_PROCESSOR") == "1",
    )
    try:
        manifest = json.loads((directory / "MANIFEST.json").read_text(encoding="utf-8"))
        total = len(manifest["vectors"])
    except (OSError, ValueError, KeyError, TypeError):
        manifest, total = {}, 0
    for error in errors:
        print(error)
    rail = "reference reader" if verifier is None else shlex.join(verifier)
    print(
        f"{SUITE}: {rail} answered {answered} of {total} cases, {not_applicable} need a YAML "
        f"processor and were not run, {len(errors)} disagreements"
    )
    if not answered or not total:
        print("no report written: no case was answered")
        return 2
    report = {
        "suite": SUITE,
        "rail": "own-reader" if verifier is None else "external",
        "verifier": {"command": verifier, "vectorsExecuted": answered, "note": rail_note},
        "corpusDigest": manifest["corpusDigest"],
        "totals": {
            "vectors": total,
            "conform": answered - len(errors),
            "fail": len(errors),
            "notApplicable": not_applicable,
            "suiteRefusals": 0,
        },
        "failures": errors,
    }
    Path(report_path).write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 1 if errors or answered + not_applicable != total else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or SUITE).splitlines()[0])
    parser.add_argument("target", nargs="?", help="a SKILL.md to parse with the reference reader")
    parser.add_argument("--json", action="store_true", help="print the answer as JSON")
    parser.add_argument("--verifier", help="run every corpus case through this verifier instead")
    args = parser.parse_args(argv)
    if args.target:
        try:
            result = answer(parse(Path(args.target).read_bytes(), yaml_check=yaml_processor()))
        except OSError as exc:
            print(f"cannot read the file: {exc}")
            return 2
        if args.json:
            print(json.dumps(result, sort_keys=True))
        elif result["outcome"] == "ok":
            print("ok " + " ".join(result["keys"]))
        else:
            print(f"refused {result['code']}" + (f" line {result['line']}" if result["line"] else ""))
        return 0
    answered, not_applicable, errors = check(args.verifier, yaml_check=yaml_processor())
    for error in errors:
        print(error)
    total = len(json.loads((ROOT / "MANIFEST.json").read_text(encoding="utf-8"))["vectors"])
    print(f"answered {answered} of {total} cases, {not_applicable} need a YAML processor")
    return 1 if errors or answered + not_applicable != total else 0


if __name__ == "__main__":
    raise SystemExit(main())
