"""Create isolated test repositories with explicit, synthetic branch authority."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import pathlib
import subprocess
from typing import Any
from unittest.mock import patch

from _branch_authority import default_branch_authority, frozen_refs


def fixture_git(root: pathlib.Path, *args: str) -> str:
    """Bootstrap only the named fixture, without caller Git configuration."""
    env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    env.update({"GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull})
    return subprocess.run(  # noqa: S603 -- fixed Git executable and explicit fixture repository
        [
            "git",
            "-C",
            str(root),
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "commit.gpgSign=false",
            "-c",
            "tag.gpgSign=false",
            *args,
        ],
        env=env,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def fixture_authority(root: pathlib.Path) -> dict[str, Any]:
    """Exercise the real authority parser with labelled fixture primary bytes."""
    origin = "https://github.com/example/workflow-fixture.git"
    fixture_git(root, "config", "remote.origin.url", origin)
    refs = frozen_refs(root)
    ref = "refs/remotes/origin/trunk"
    if not any(row["ref"] == ref for row in refs):
        fixture_git(root, "update-ref", ref, "HEAD")
        refs = frozen_refs(root)
    tip = next(row["object"] for row in refs if row["ref"] == ref)
    api = json.dumps({"full_name": "example/workflow-fixture", "default_branch": "trunk"}).encode()
    remote = f"ref: refs/heads/trunk\tHEAD\n{tip}\tHEAD\n{tip}\trefs/heads/trunk\n".encode()

    def record(argv: list[str], data: bytes) -> dict[str, Any]:
        return {
            "argv": argv,
            "returncode": 0,
            "testFixture": "synthetic primary metadata",
            "stdout": {
                "base64": base64.b64encode(data).decode(),
                "bytes": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
            },
            "stderr": {"base64": "", "bytes": 0, "sha256": hashlib.sha256(b"").hexdigest()},
        }

    return {
        "version": "branch-authority/v1",
        "origin": origin,
        "selected_head": fixture_git(root, "rev-parse", "HEAD"),
        "frozen_refs": refs,
        "authority": default_branch_authority(origin, api, remote, refs),
        "primary": {
            "repository": record(
                ["gh", "api", "--method", "GET", "repos/example/workflow-fixture"], api
            ),
            "remote_head": record(
                ["git", "ls-remote", "--symref", origin, "HEAD", "refs/heads/trunk"], remote
            ),
        },
    }


def fixture_source(gate: Any, root: pathlib.Path) -> Any:
    """Bind a fixture to its own push context and restore the enclosing CI context."""
    selected = fixture_git(root, "rev-parse", "HEAD")
    context = {"GITHUB_SHA": selected, "GITHUB_HEAD_SHA": selected, "GITHUB_EVENT_NAME": "push"}
    with patch.dict(os.environ, context):
        return gate.Source(root, fixture_authority(root))
