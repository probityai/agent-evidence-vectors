"""Bind the workflow mirror to captured repository metadata and complete Git history."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import subprocess
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from _gate_json import decode_json


def repository_origin(origin: str) -> str:
    """Identify the repository from the exact accepted origin representations."""
    if not isinstance(origin, str):
        raise ValueError("origin is not a bound GitHub repository")
    match = re.fullmatch(
        r"(?:https://github\.com/|git@github\.com:)([^/]+/[^/]+?)(?:\.git)?", origin
    )
    if match is None:
        raise ValueError("origin is not a bound GitHub repository")
    return match.group(1)


def default_branch_authority(
    origin: str,
    api_bytes: bytes,
    remote_bytes: bytes,
    refs: object,
) -> dict[str, str]:
    """Require two primary sources and keep the frozen local tip separate."""
    repository = repository_origin(origin)
    api = decode_json(api_bytes)
    if not isinstance(api, dict) or api.get("full_name") != repository:
        raise ValueError("repository API identifies a different origin")
    branch = api.get("default_branch")
    if not isinstance(branch, str) or not branch:
        raise ValueError("repository API lacks a default branch")
    full_ref = "refs/heads/" + branch
    if subprocess.run(
        ["git", "check-ref-format", full_ref],
        capture_output=True,
        check=False,
        env=git_environment(),
    ).returncode:
        raise ValueError("published default branch is not a valid branch ref")
    live_head = remote_authority(remote_bytes, full_ref)
    remote_ref = "refs/remotes/origin/" + branch
    return {
        "repository": repository,
        "default_branch": branch,
        "remote_default_ref": full_ref,
        "live_remote_tip": live_head,
        "frozen_published_ref": remote_ref,
        "frozen_published_tip": frozen_branch_tip(refs, remote_ref),
        "scope": "frozen local push mirror; live metadata does not update frozen objects",
    }


def remote_authority(remote_bytes: bytes, full_ref: str) -> str:
    """Require one direct tip and its matching explicit remote HEAD target."""
    records = {}
    for line in remote_bytes.decode("utf-8").splitlines():
        fields = line.split("\t")
        if len(fields) != 2:
            raise ValueError("remote HEAD response contains a malformed record")
        value, name = fields
        if value.startswith("ref: ") and name != "HEAD":
            raise ValueError("remote symbolic authority does not identify HEAD")
        key = "symbolic HEAD" if value.startswith("ref: ") else name
        if key in records:
            raise ValueError("remote HEAD response contains duplicate authority")
        records[key] = value
    if set(records) != {"symbolic HEAD", "HEAD", full_ref}:
        raise ValueError("remote HEAD response is incomplete or has extra refs")
    live_head = records["HEAD"]
    if (
        records["symbolic HEAD"] != "ref: " + full_ref
        or records[full_ref] != live_head
        or re.fullmatch(r"[0-9a-f]{40}", live_head) is None
    ):
        raise ValueError("repository API and remote HEAD authority disagree")
    return live_head


def frozen_branch_tip(refs: object, remote_ref: str) -> str:
    """Require exactly one direct frozen reference for the selected branch."""
    if not isinstance(refs, list) or any(not isinstance(row, dict) for row in refs):
        raise ValueError("frozen tracking refs are not object records")
    selected = [item for item in refs if item.get("ref") == remote_ref]
    if len(selected) != 1:
        raise ValueError("frozen history lacks a unique published branch tip")
    tip = selected[0].get("object")
    if selected[0].get("symref") or not isinstance(tip, str):
        raise ValueError("frozen published branch is not a direct object ref")
    if re.fullmatch(r"[0-9a-f]{40}", tip) is None:
        raise ValueError("frozen published branch tip is not a SHA-1 object")
    return tip


def git(root: Path, *args: str, input_bytes: bytes | None = None) -> bytes:
    """Read local objects without permitting a lazy network fetch."""
    return subprocess.run(
        ["git", "-C", str(root), *args],
        input=input_bytes,
        capture_output=True,
        check=True,
        env=git_environment(root),
    ).stdout


def git_environment(
    root: Path | None = None, *, base: Mapping[str, str] | None = None
) -> dict[str, str]:
    """Bind Git to command arguments; a graft cannot establish original history."""
    env = {
        **(os.environ if base is None else base),
        "GIT_NO_LAZY_FETCH": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
    }
    # Hooks can inherit a different repository, index or object store. Those
    # selectors must not override an explicit root, including during bootstrap.
    for key in (
        "GIT_DIR",
        "GIT_WORK_TREE",
        "GIT_COMMON_DIR",
        "GIT_INDEX_FILE",
        "GIT_OBJECT_DIRECTORY",
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        "GIT_NAMESPACE",
        "GIT_SHALLOW_FILE",
        "GIT_CEILING_DIRECTORIES",
        "GIT_DISCOVERY_ACROSS_FILESYSTEM",
    ):
        env.pop(key, None)
    if root is None:
        return env
    actual = (
        subprocess.run(
            [
                "git",
                "-C",
                str(root),
                "rev-parse",
                "--path-format=absolute",
                "--git-path",
                "info/grafts",
            ],
            capture_output=True,
            check=True,
            env=env,
        )
        .stdout.decode()
        .strip()
    )
    paths = [Path(actual)]
    if configured := env.get("GIT_GRAFT_FILE"):
        path = Path(configured)
        paths.append(path if path.is_absolute() else root / path)
    for path in paths:
        if path.is_symlink() and not path.exists():
            raise ValueError("graft input is not an available regular file")
        if path.exists() and (not path.is_file() or path.read_bytes().strip()):
            raise ValueError("graft input cannot establish original-object history")
    return env


def frozen_refs(root: Path) -> list[dict[str, Any]]:
    """Read actual direct and symbolic tracking refs without changing them."""
    result = []
    for line in (
        git(
            root,
            "for-each-ref",
            "--format=%(refname)\t%(objectname)\t%(symref)",
            "refs/remotes/origin",
        )
        .decode("utf-8")
        .splitlines()
    ):
        fields = line.split("\t")
        if len(fields) != 3:
            raise ValueError("frozen tracking refs have a malformed record")
        result.append({"ref": fields[0], "object": fields[1], "symref": fields[2] or None})
    return result


def require_frozen_commit(root: Path, authority: dict[str, str]) -> None:
    """Check the bound direct commit and origin in each actual restored clone."""
    if (
        repository_origin(git(root, "remote", "get-url", "origin").decode().strip())
        != (authority["repository"])
    ):
        raise ValueError("frozen checkout origin does not match branch authority")
    ref = "refs/remotes/origin/" + authority["default_branch"]
    if authority["frozen_published_ref"] != ref:
        raise ValueError("frozen branch ref does not match branch authority")
    tip = frozen_branch_tip(frozen_refs(root), ref)
    if tip != authority["frozen_published_tip"]:
        raise ValueError("frozen checkout branch tip changed")
    if git(root, "cat-file", "-t", tip) != b"commit\n":
        raise ValueError("frozen branch tip is not an available commit object")


def require_closure(root: Path, head: str, tip: str) -> dict[str, Any]:
    """Refuse history the shared snapshot cannot carry through its selected parent."""
    for oid in (head, tip):
        if re.fullmatch(r"[0-9a-f]{40}", oid) is None:
            raise ValueError("history coordinate is not a SHA-1 commit")
        if git(root, "cat-file", "-t", oid) != b"commit\n":
            raise ValueError("history coordinate is not an available commit")
    if git(root, "rev-parse", "--is-shallow-repository").strip() != b"false":
        raise ValueError("shallow history cannot establish complete snapshot custody")
    promisor = subprocess.run(
        ["git", "-C", str(root), "config", "--get-regexp", r"^remote\..*\.promisor$"],
        capture_output=True,
        check=False,
        env=git_environment(root),
    )
    if promisor.returncode not in (0, 1) or promisor.stdout:
        raise ValueError("partial history cannot establish complete snapshot custody")
    if subprocess.run(
        ["git", "-C", str(root), "merge-base", "--is-ancestor", tip, head],
        capture_output=True,
        check=False,
        env=git_environment(root),
    ).returncode:
        raise ValueError("required default history is outside the selected snapshot closure")
    objects = git(root, "rev-list", "--objects", "--missing=error", head)
    ids = [line.split(b" ", 1)[0] for line in objects.splitlines()]
    types = git(root, "cat-file", "--batch-check", input_bytes=b"\n".join(ids) + b"\n")
    rows = types.splitlines()
    if len(rows) != len(ids) or any(
        len(row.split()) != 3 or row.split()[1] not in (b"commit", b"tree", b"blob", b"tag")
        for row in rows
    ):
        raise ValueError("selected snapshot history contains unavailable objects")
    return {
        "transport": "complete selected-HEAD closure",
        "head": head,
        "tip": tip,
        "objects": len(ids),
        "objectListSha256": hashlib.sha256(objects).hexdigest(),
    }


def capture_process(directory: Path, name: str, argv: list[str], root: Path) -> dict[str, Any]:
    """Preserve primary output and actual status before interpreting it."""
    started = datetime.now(UTC).isoformat()
    process = subprocess.run(
        argv,
        cwd=root,
        capture_output=True,
        check=False,
        env=git_environment(root) if argv[0] == "git" else None,
    )
    record = {
        "argv": argv,
        "startedAtUTC": started,
        "finishedAtUTC": datetime.now(UTC).isoformat(),
        "returncode": process.returncode,
    }
    for stream in ("stdout", "stderr"):
        data = getattr(process, stream)
        (directory / (name + "." + stream + ".original")).write_bytes(data)
        record[stream] = {
            "base64": base64.b64encode(data).decode(),
            "bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
        }
    (directory / (name + ".process.json")).write_text(json.dumps(record, indent=2) + "\n")
    if process.returncode:
        raise ValueError(f"{name} primary capture failed (exit {process.returncode})")
    return record


def primary_bytes(record: object, argv: list[str]) -> bytes:
    """Check the exact primary command and original streams inside a request."""
    if not isinstance(record, dict):
        raise ValueError("branch authority primary record is not an object")
    if record.get("argv") != argv or type(record.get("returncode")) is not int:
        raise ValueError("branch authority primary command differs from its contract")
    if record["returncode"] != 0:
        raise ValueError("branch authority primary command did not succeed")
    decoded = {}
    for stream in ("stdout", "stderr"):
        row = record.get(stream)
        if not isinstance(row, dict) or not isinstance(row.get("base64"), str):
            raise ValueError("branch authority original stream is not a byte record")
        data = base64.b64decode(row["base64"], validate=True)
        if type(row.get("bytes")) is not int or row["bytes"] != len(data):
            raise ValueError("branch authority original stream size changed")
        if row.get("sha256") != hashlib.sha256(data).hexdigest():
            raise ValueError("branch authority original stream hash changed")
        decoded[stream] = data
    return decoded["stdout"]


def packet_authority(packet: dict[str, Any]) -> dict[str, str]:
    """Reparse original metadata; a precomputed branch string is never authority."""
    if not isinstance(packet, dict) or packet.get("version") != "branch-authority/v1":
        raise ValueError("branch authority packet version is unsupported")
    origin = packet.get("origin")
    if not isinstance(origin, str):
        raise ValueError("origin is not a bound GitHub repository")
    repository = repository_origin(origin)
    primary = packet.get("primary")
    if not isinstance(primary, dict):
        raise ValueError("branch authority primary captures are not an object")
    api = primary_bytes(
        primary.get("repository"), ["gh", "api", "--method", "GET", "repos/" + repository]
    )
    decoded = decode_json(api)
    if not isinstance(decoded, dict):
        raise ValueError("repository API is not an object")
    branch = decoded.get("default_branch")
    if not isinstance(branch, str):
        raise ValueError("repository API lacks a default branch")
    remote = primary_bytes(
        primary.get("remote_head"),
        ["git", "ls-remote", "--symref", origin, "HEAD", "refs/heads/" + branch],
    )
    authority = default_branch_authority(origin, api, remote, packet.get("frozen_refs"))
    if packet.get("authority") != authority:
        raise ValueError("branch authority differs from its original primary bytes")
    if authority["frozen_published_tip"] != authority["live_remote_tip"]:
        raise ValueError("local published tip differs from captured current remote authority")
    return authority


def require_packet(root: Path, packet: dict[str, Any]) -> dict[str, str]:
    """Bind actual source, direct default ref, and complete parent closure."""
    authority = packet_authority(packet)
    head = git(root, "rev-parse", "HEAD").decode().strip()
    if packet.get("selected_head") != head:
        raise ValueError("branch authority names another selected source commit")
    require_frozen_commit(root, authority)
    require_closure(root, head, authority["frozen_published_tip"])
    return authority


def capture_authority(root: Path, directory: Path) -> dict[str, Any]:
    """Produce one immutable metadata packet before any allocation or workflow runs."""
    directory.mkdir(parents=True, exist_ok=False)
    origin = git(root, "remote", "get-url", "origin").decode().strip()
    repository = repository_origin(origin)
    api = capture_process(
        directory, "repository", ["gh", "api", "--method", "GET", "repos/" + repository], root
    )
    decoded = decode_json(base64.b64decode(api["stdout"]["base64"], validate=True))
    if not isinstance(decoded, dict) or not isinstance(decoded.get("default_branch"), str):
        raise ValueError("repository API lacks a default branch")
    branch = decoded["default_branch"]
    # Validate the ref before sending it as a remote selector.
    git(root, "check-ref-format", "refs/heads/" + branch)
    remote = capture_process(
        directory,
        "remote-head",
        ["git", "ls-remote", "--symref", origin, "HEAD", "refs/heads/" + branch],
        root,
    )
    refs = [row for row in frozen_refs(root) if row["ref"] == "refs/remotes/origin/" + branch]
    packet = {
        "version": "branch-authority/v1",
        "origin": origin,
        "selected_head": git(root, "rev-parse", "HEAD").decode().strip(),
        "primary": {"repository": api, "remote_head": remote},
        "frozen_refs": refs,
    }
    packet["authority"] = default_branch_authority(
        origin,
        base64.b64decode(api["stdout"]["base64"], validate=True),
        base64.b64decode(remote["stdout"]["base64"], validate=True),
        refs,
    )
    (directory / "branch-authority.json").write_text(json.dumps(packet, indent=2) + "\n")
    try:
        require_packet(root, packet)
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        (directory / "refusal.json").write_text(json.dumps({"reason": str(exc)}) + "\n")
        raise
    return packet


def restore_authority(root: Path, packet: dict[str, Any], directory: Path) -> None:
    """Restore only the authenticated tracking ref; cached origin/HEAD stays unused."""
    authority = packet_authority(packet)
    head = git(root, "rev-parse", "HEAD").decode().strip()
    if head != packet.get("selected_head"):
        raise ValueError("transport checkout names another selected commit")
    if (
        repository_origin(git(root, "remote", "get-url", "origin").decode().strip())
        != (authority["repository"])
    ):
        raise ValueError("transport checkout origin changed")
    proof = require_closure(root, head, authority["frozen_published_tip"])
    before = frozen_refs(root)
    git(
        root,
        "update-ref",
        "--no-deref",
        authority["frozen_published_ref"],
        authority["frozen_published_tip"],
    )
    require_packet(root, packet)
    (directory / "branch-transport.json").write_text(
        json.dumps(
            {
                "before": before,
                "after": frozen_refs(root),
                "closure": proof,
                "authority": authority,
                "cachedOriginHeadUsed": False,
            },
            indent=2,
        )
        + "\n"
    )
