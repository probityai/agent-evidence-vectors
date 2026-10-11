"""Resolve the pinned setup-go file contract and retain its actual inputs."""

from __future__ import annotations

import base64
import hashlib
import os
import pathlib
import re
import stat
import subprocess
from typing import Any

SETUP_GO_REVISION = "40f1582b2485089dde7abd97c1529aa768e1baff"
# ECMAScript WhiteSpace plus LineTerminator; Python strip differs at BOM/NEL.
JS_TRIM = (
    "\u0009\u000a\u000b\u000c\u000d\u0020\u00a0\u1680"
    "\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a"
    "\u2028\u2029\u202f\u205f\u3000\ufeff"
)
GO_DIRECTIVE = re.compile(r"(?:\A|(?<=[\n\r\u2028\u2029]))go ([0-9]+(?:\.[0-9]+)*)")


def file_origin(root: pathlib.Path, filename: str, raw: bytes) -> dict[str, Any]:
    """Distinguish captured environment input from a matching frozen Git blob."""
    path = pathlib.Path(os.path.join(str(root), filename))
    resolved = path.resolve()
    record: dict[str, Any] = {
        "resolved_path": str(resolved),
        "link_text": os.readlink(path) if path.is_symlink() else None,
        "inside_workspace": resolved.is_relative_to(root.resolve()),
        "matches_frozen_blob": False,
    }
    if not record["inside_workspace"]:
        record["source_class"] = "external captured input"
        return record
    relative = resolved.relative_to(root.resolve()).as_posix()
    try:
        commit = (
            subprocess.check_output(
                ["git", "-C", str(root), "rev-parse", "HEAD"], stderr=subprocess.DEVNULL
            )
            .decode()
            .strip()
        )  # noqa: S603 -- read this job's Git source only
        blob = subprocess.check_output(
            ["git", "-C", str(root), "show", f"{commit}:{relative}"], stderr=subprocess.DEVNULL
        )  # noqa: S603 -- exact commit and physical workspace path
    except subprocess.CalledProcessError:
        record["source_class"] = "untracked captured input"
        return record
    record.update(
        source_class="tracked workspace input",
        source_commit=commit,
        source_path=relative,
        frozen_blob_sha256=hashlib.sha256(blob).hexdigest(),
        matches_frozen_blob=blob == raw,
    )
    return record


def read_version_file(root: pathlib.Path, filename: str) -> bytes:
    """Read a regular file without normalizing a trailing slash or blocking on a FIFO."""
    path = os.path.join(str(root), filename)
    descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
    if not stat.S_ISREG(os.fstat(descriptor).st_mode):
        os.close(descriptor)
        raise ValueError("native Go version input must be a regular file")
    with os.fdopen(descriptor, "rb") as stream:
        return stream.read()


def input_text(value: Any) -> str:
    """Match Actions' null and Boolean rendering, then core.getInput's trim."""
    if value is None:
        return ""
    text = str(value).lower() if isinstance(value, bool) else str(value)
    return text.strip(JS_TRIM)


def go_selector(inputs: dict[str, Any], root: pathlib.Path, probe: dict[str, Any]) -> str:
    """Mirror setup-go v5's precedence and file parser on retained job inputs.

    Relative action inputs resolve from the workspace, independently of shell
    working-directory defaults. The pinned v5 parser reads the go directive,
    not the toolchain directive. An omitted selection remains empty so that
    the native provider refuses rather than guessing the runner's Go version.
    """
    version = input_text(inputs.get("go-version", ""))
    filename = input_text(inputs.get("go-version-file", ""))
    if version:
        probe["selector_source"] = "go-version"
        if filename:
            probe["ignored_go_version_file"] = filename
        return version
    if not filename:
        probe["selector_source"] = "missing"
        return ""
    probe["selector_source"] = "go-version-file"
    probe["requested_go_version_file"] = filename
    raw = read_version_file(root, filename)
    contents = raw.decode("utf-8", errors="replace")
    probe["go_version_file"] = {
        "input": filename,
        "path": os.path.join(str(root), filename),
        "bytes": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "contents": contents,
        "contents_base64": base64.b64encode(raw).decode("ascii"),
        "valid_utf8": contents.encode("utf-8") == raw,
        **file_origin(root, filename, raw),
    }
    if os.path.basename(filename) in {"go.mod", "go.work"}:
        match = GO_DIRECTIVE.search(contents)
        return match[1] if match else ""
    return contents.strip(JS_TRIM)
