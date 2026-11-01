"""Build the deterministic SKILL.md frontmatter parse cases.

Each case is the exact octets of one ``SKILL.md`` and the outcome the parse
algorithm in ``SPEC.md`` assigns it: the top-level keys and the body for an
accepted file, a refusal code (and the line, where the step names one) for a
refused one. Standard library only.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
SUITE = "skill-frontmatter-parse/v1"


@dataclass(frozen=True)
class Case:
    """One input file, the step it exercises and the outcome it must get."""

    id: str
    step: str
    description: str
    data: bytes
    expected: dict[str, Any]
    needs_yaml: bool = False


def _filled(head: str, fill: str, octets: int, tail: str) -> bytes:
    """``head`` + ``fill`` repeated to ``octets`` + ``tail``, UTF-8 encoded."""
    return (head + fill * (octets // len(fill)) + tail).encode("utf-8")


def ok(keys: tuple[str, ...], body: str | None = None) -> dict[str, Any]:
    """An accepted file: its top-level keys in order and, when stated, its body."""
    expected: dict[str, Any] = {"outcome": "ok", "keys": list(keys)}
    if body is not None:
        expected["body"] = body
    return expected


def refused(code: str, line: int | None = None) -> dict[str, Any]:
    """A refused file: the code, and the 1-based line when the step names one."""
    expected: dict[str, Any] = {"outcome": "error", "code": code}
    if line is not None:
        expected["line"] = line
    return expected


def case(
    id: str,  # noqa: A002
    step: str,
    description: str,
    data: bytes,
    expected: dict[str, Any],
    *,
    needs_yaml: bool = False,
) -> Case:
    """Build a case; the keyword form keeps the table below one case per block."""
    return Case(id, step, description, data, expected, needs_yaml)


# The order is the order of the README table.
CASES = (
    case(
        "minimal",
        "all",
        "two required keys, body follows",
        b"---\nname: a\ndescription: b\n---\nBody\n",
        ok(("name", "description"), "Body\n"),
    ),
    case(
        "no-body",
        "6",
        "closing delimiter is the last line, no terminator",
        b"---\nname: a\n---",
        ok(("name",), ""),
    ),
    case(
        "crlf",
        "2",
        "CRLF line endings accepted, body bytes untouched",
        b"---\r\nname: a\r\ndescription: b\r\n---\r\nB\r\nC\r\n",
        ok(("name", "description"), "B\r\nC\r\n"),
    ),
    case(
        "cr-only",
        "2",
        "lone CR is a line terminator",
        b"---\rname: a\r---\rB",
        ok(("name",), "B"),
    ),
    case(
        "mixed-terminators",
        "2",
        "LF, CRLF and CR mixed in one file",
        b"---\nname: a\r\ndescription: b\r---\nB",
        ok(("name", "description"), "B"),
    ),
    case(
        "trailing-space-on-delimiters",
        "3",
        "delimiter lines tolerate trailing space and tab",
        b"---  \t\nname: a\n--- \t\nB",
        ok(("name",), "B"),
    ),
    case(
        "unicode-line-separator-is-content",
        "2",
        "U+2028 is not a line terminator",
        '---\nname: "a\u2028b"\n---\n'.encode(),
        ok(("name",), ""),
    ),
    case(
        "dashes-inside-value",
        "6",
        "--- inside a value does not close the block",
        b"---\nname: a\ndescription: see a---b table\n---\nB",
        ok(("name", "description"), "B"),
    ),
    case(
        "dashes-inside-body",
        "6",
        "a later --- line in the body is body text",
        b"---\nname: a\n---\nx\n---\ny\n",
        ok(("name",), "x\n---\ny\n"),
    ),
    case(
        "comment-lines",
        "9",
        "blank and comment lines in the block are ignored",
        b"---\n# note\n\nname: a\n   \n# end\n---\n",
        ok(("name",), ""),
    ),
    case(
        "nested-mapping",
        "9",
        "indented lines belong to the preceding key",
        b"---\nname: a\nmetadata:\n  name: inner\n  author: x\n---\n",
        ok(("name", "metadata"), ""),
    ),
    case(
        "same-key-nested-not-duplicate",
        "10",
        "a key repeated only at depth is not a top-level repeat",
        b"---\nname: a\nmetadata:\n  name: b\n---\n",
        ok(("name", "metadata"), ""),
    ),
    case(
        "block-scalar-contents",
        "9",
        "block scalar lines are not entries",
        b"---\nname: a\ndescription: |\n  name: not-a-key\n  more\n---\n",
        ok(("name", "description"), ""),
    ),
    case(
        "sequence-at-key-indent",
        "9",
        "a column-0 sequence continues the preceding empty-valued key",
        b"---\nname: a\ntags:\n- x\n- y\nlicense: z\n---\n",
        ok(("name", "tags", "license"), ""),
    ),
    case(
        "quoted-keys",
        "10",
        "quoted keys are keys",
        b"---\n\"name\": a\n'description': b\n---\n",
        ok(("name", "description"), ""),
    ),
    case(
        "document-end-in-body",
        "4",
        "a ... line in the body is body text",
        b"---\nname: a\n---\n...\nx\n",
        ok(("name",), "...\nx\n"),
    ),
    case(
        "hyphen-key",
        "10",
        "a key may begin with a hyphen when no space follows",
        b"---\n-x: 1\n---\n",
        ok(("-x",), ""),
    ),
    case(
        "body-keeps-bom-after-frontmatter",
        "2",
        "a U+FEFF after the frontmatter is body text",
        "---\nname: a\n---\n\ufeffB".encode(),
        ok(("name",), "\ufeffB"),
    ),
    case(
        "empty-file",
        "3",
        "an empty file has no opening delimiter",
        b"",
        refused("no-opening-delimiter", line=1),
    ),
    case(
        "no-delimiter",
        "3",
        "plain markdown declares nothing and is refused",
        b"# Title\n\nbody\n",
        refused("no-opening-delimiter", line=1),
    ),
    case(
        "blank-line-before-opening",
        "3",
        "opening delimiter must be line 1",
        b"\n---\nname: a\ndescription: b\n---\n",
        refused("no-opening-delimiter", line=1),
    ),
    case(
        "html-comment-before-opening",
        "3",
        "a comment before the delimiter is refused",
        b"<!-- x -->\n---\nname: a\ndescription: b\n---\n",
        refused("no-opening-delimiter", line=1),
    ),
    case(
        "code-fence-wrapped",
        "3",
        "a fenced frontmatter is refused",
        b"```yaml\n---\nname: a\ndescription: b\n---\n```\n",
        refused("no-opening-delimiter", line=1),
    ),
    case(
        "four-dash-opening",
        "3",
        "four hyphens do not open",
        b"----\nname: a\n---\n",
        refused("no-opening-delimiter", line=1),
    ),
    case(
        "leading-space-opening",
        "3",
        "an indented opening does not open",
        b" ---\nname: a\n---\n",
        refused("no-opening-delimiter", line=1),
    ),
    case(
        "bom",
        "2",
        "a leading BOM is refused by name, not read as no frontmatter",
        "\ufeff---\nname: a\ndescription: b\n---\n".encode(),
        refused("byte-order-mark", line=1),
    ),
    case(
        "invalid-utf8",
        "2",
        "invalid UTF-8 octets",
        bytes.fromhex("2d2d2d0a6e616d653a2061ff0a2d2d2d0a"),
        refused("invalid-utf8"),
    ),
    case(
        "overlong-utf8",
        "2",
        "overlong encoding is invalid UTF-8",
        bytes.fromhex("2d2d2d0a6e616d653a2061c0af0a2d2d2d0a"),
        refused("invalid-utf8"),
    ),
    case(
        "unterminated",
        "6",
        "no closing delimiter: refused, never the rest of the file",
        b"---\nname: a\ndescription: b\nbody text\n",
        refused("unterminated-frontmatter", line=1),
    ),
    case(
        "four-dash-closing",
        "6",
        "four hyphens do not close",
        b"---\nname: a\n----\nB\n",
        refused("unterminated-frontmatter", line=1),
    ),
    case(
        "indented-closing",
        "6",
        "an indented --- does not close",
        b"---\nname: a\n ---\nB\n",
        refused("unterminated-frontmatter", line=1),
    ),
    case(
        "closing-with-text",
        "6",
        "--- followed by text is not a closing line",
        b"---\nname: a\n--- x\nB\n",
        refused("unterminated-frontmatter", line=1),
    ),
    case(
        "opening-only",
        "3",
        "a file that is only the opening delimiter",
        b"---\n",
        refused("unterminated-frontmatter", line=1),
    ),
    case(
        "empty-frontmatter",
        "8",
        "two adjacent delimiters declare nothing",
        b"---\n---\nB\n",
        refused("frontmatter-empty", line=2),
    ),
    case(
        "comment-only-frontmatter",
        "8",
        "comments alone declare nothing",
        b"---\n# c\n\n---\nB\n",
        refused("frontmatter-empty", line=2),
    ),
    case(
        "document-end",
        "7",
        "a ... line is a document-end marker",
        b"---\nname: a\n...\ndescription: b\n---\nB\n",
        refused("document-end-marker", line=3),
    ),
    case(
        "document-end-with-comment",
        "7",
        "... followed by a comment is still the marker",
        b"---\nname: a\n... # end\n---\n",
        refused("document-end-marker", line=3),
    ),
    case(
        "document-end-first",
        "7",
        "a marker is reported ahead of structural faults",
        b"---\n- x\n...\n---\n",
        refused("document-end-marker", line=3),
    ),
    case(
        "document-start-with-content",
        "7",
        "--- followed by content starts a second document",
        b"---\nname: a\n--- x\ndescription: b\n---\nB\n",
        refused("document-start-marker", line=3),
    ),
    case(
        "duplicate-same-value",
        "10",
        "a repeated key is refused even when the values agree",
        b"---\nname: a\nname: a\n---\n",
        refused("duplicate-key", line=3),
    ),
    case(
        "duplicate-different-value",
        "10",
        "a repeated key is refused when the values differ",
        b"---\nname: a\ndescription: b\nname: c\n---\n",
        refused("duplicate-key", line=4),
    ),
    case(
        "duplicate-unknown-key",
        "10",
        "the rule covers keys the parser does not read",
        b"---\nname: a\nx-vendor: 1\nx-vendor: 2\n---\n",
        refused("duplicate-key", line=4),
    ),
    case(
        "duplicate-quoted-and-plain",
        "10",
        "a quoted key and a plain key are the same key",
        b'---\nname: a\n"name": b\n---\n',
        refused("duplicate-key", line=3),
    ),
    case(
        "duplicate-escaped",
        "10",
        "an escaped quoted key is compared decoded",
        b'---\nab: 1\n"a\\/b": 2\n"a/b": 3\n---\n',
        refused("duplicate-key", line=4),
    ),
    case(
        "scalar-root",
        "9",
        "a bare scalar is not a mapping",
        b"---\njust a string\n---\n",
        refused("root-not-block-mapping", line=2),
    ),
    case(
        "sequence-root",
        "9",
        "a sequence is not a mapping",
        b"---\n- a\n- b\n---\n",
        refused("root-not-block-mapping", line=2),
    ),
    case(
        "flow-mapping-root",
        "9",
        "a flow mapping root is not a block mapping",
        b"---\n{name: a, description: b}\n---\n",
        refused("root-not-block-mapping", line=2),
    ),
    case(
        "flow-sequence-root",
        "9",
        "a flow sequence root is not a mapping",
        b"---\n[a, b]\n---\n",
        refused("root-not-block-mapping", line=2),
    ),
    case(
        "indented-root",
        "9",
        "entries must start at column 0",
        b"---\n  name: a\n---\n",
        refused("root-not-block-mapping", line=2),
    ),
    case(
        "tab-root",
        "9",
        "a tab is not indentation",
        b"---\n\tname: a\n---\n",
        refused("root-not-block-mapping", line=2),
    ),
    case(
        "block-scalar-root",
        "9",
        "a block scalar root is not a mapping",
        b"---\n|\n  name: a\n---\n",
        refused("root-not-block-mapping", line=2),
    ),
    case(
        "directive-line",
        "10",
        "a % directive is not an entry",
        b"---\n%YAML 1.2\nname: a\n---\n",
        refused("root-not-block-mapping", line=2),
    ),
    case(
        "stray-scalar-after-entry",
        "10",
        "a column-0 line that is no entry",
        b"---\nname: a\nstray words\n---\n",
        refused("invalid-entry", line=3),
    ),
    case(
        "sequence-after-valued-key",
        "10",
        "a column-0 sequence entry after a valued key",
        b"---\nname: a\n- x\n---\n",
        refused("invalid-entry", line=3),
    ),
    case(
        "sequence-after-nested-content",
        "10",
        "a column-0 sequence entry after indented content",
        b"---\ntags:\n  - a\n- b\n---\n",
        refused("invalid-entry", line=4),
    ),
    case(
        "key-without-space",
        "10",
        "name:value is a scalar, not an entry",
        b"---\nname: a\ndescription:b\n---\n",
        refused("invalid-entry", line=3),
    ),
    case(
        "multiline-quoted-key",
        "10",
        "an implicit key is on one line",
        b'---\nname: a\n"desc\nription": b\n---\n',
        refused("invalid-entry", line=3),
    ),
    case(
        "nul-in-block",
        "8",
        "NUL in the block",
        b"---\nname: a\x00b\n---\n",
        refused("control-character"),
    ),
    case(
        "escape-in-block",
        "8",
        "ESC in the block",
        b"---\nname: a\x1bb\n---\n",
        refused("control-character"),
    ),
    case(
        "frontmatter-too-large",
        "5",
        "a block over 65536 octets",
        _filled("---\nname: a\ndescription: ", "x", 65536, "\n---\n"),
        refused("frontmatter-too-large", line=2),
    ),
    case(
        "frontmatter-at-limit",
        "5",
        "a block of exactly 65536 octets is accepted",
        _filled("---\nname: a\ndescription: ", "x", 65514, "\n---\n"),
        ok(("name", "description")),
    ),
    case(
        "file-too-large",
        "1",
        "a file over 1048576 octets",
        _filled("---\nname: a\ndescription: b\n---\n", "x", 1048576, ""),
        refused("file-too-large"),
    ),
    case(
        "file-at-limit",
        "1",
        "a file of exactly 1048576 octets is accepted",
        _filled("---\nname: a\ndescription: b\n---\n", "x", 1048545, ""),
        ok(("name", "description")),
    ),
    case(
        "yaml-syntax-error",
        "11",
        "a structurally valid block the YAML processor refuses",
        b"---\nname: a\ndescription: [unclosed\n---\n",
        refused("yaml-syntax-error"),
        needs_yaml=True,
    ),
    case(
        "yaml-bad-indent",
        "11",
        "inconsistent indentation under a key",
        b"---\nname: a\nmetadata:\n    a: 1\n  b: 2\n---\n",
        refused("yaml-syntax-error"),
        needs_yaml=True,
    ),
)


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()


def corpus_digest(manifest: dict[str, Any], root: str) -> str:
    """Recompute the digest from the committed files, not their declared hashes."""
    base = Path(root)
    entries = []
    for entry in manifest["vectors"]:
        directory = base / entry["path"]
        declared = entry["files"]
        actual = {p.name for p in directory.iterdir() if p.is_file()}
        if actual != set(declared):
            raise ValueError(f"{entry['id']}: file set changed")
        files = {name: _digest((directory / name).read_bytes()) for name in declared}
        if files != declared:
            raise ValueError(f"{entry['id']}: file digest mismatch")
        entries.append({**entry, "files": files})
    return _digest(_json(entries))


def generate(root: Path = ROOT) -> dict[str, Any]:
    """Write the cases under ``root`` and return the manifest.

    Parameters
    ----------
    root : Path
        Output corpus directory.

    Returns
    -------
    dict
        Manifest with the expected outcome of every case and its byte commitments.
    """
    entries = []
    for item in CASES:
        directory = root / "cases" / item.id
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "SKILL.md").write_bytes(item.data)
        entry: dict[str, Any] = {
            "id": item.id,
            "path": f"cases/{item.id}",
            "files": {"SKILL.md": _digest(item.data)},
            "step": item.step,
            "description": item.description,
            "expected": item.expected,
        }
        if item.needs_yaml:
            entry["needsYaml"] = True
        entries.append(entry)
    manifest: dict[str, Any] = {
        "suite": SUITE,
        "vectors": entries,
        "verifierContract": "verifier SKILL.md --json",
        "specification": {
            "kind": "proposal",
            "file": "SPEC.md",
            "sha256": _digest((root / "SPEC.md").read_bytes()),
            "base": (
                "agentskills/agentskills docs/specification.mdx at "
                "27a9f0c075e876ad632fc2e88b8866c5dc8ca15c"
            ),
        },
    }
    manifest["corpusDigest"] = _digest(_json(entries))
    manifest["counts"] = {
        "accepted": sum(e["expected"]["outcome"] == "ok" for e in entries),
        "refused": sum(e["expected"]["outcome"] == "error" for e in entries),
    }
    (root / "MANIFEST.json").write_bytes(_json(manifest))
    return manifest


if __name__ == "__main__":
    generate()
