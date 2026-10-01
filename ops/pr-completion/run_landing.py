"""Execute the unchanged PR Completion guards on an authenticated runner."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any


def capture(command: list[str], destination: Path, repository: Path) -> dict[str, Any]:
    """Retain and display a guard result, refusing unsuccessful executions.

    Parameters
    ----------
    command : list[str]
        Argument vector for the shipped watcher or landing helper.
    destination : Path
        Audit JSON file outside the candidate checkout.
    repository : Path
        Checkout of the exact approved PR head.

    Returns
    -------
    dict[str, Any]
        Parsed guard result after a successful execution.

    Raises
    ------
    RuntimeError
        If the guard exits unsuccessfully or returns a non-object result.
    """
    result = subprocess.run(
        command, cwd=repository, text=True, capture_output=True, check=False
    )
    destination.write_text(result.stdout)
    print(result.stdout, flush=True)
    if result.stderr:
        print(result.stderr, file=sys.stderr, flush=True)
    if result.returncode:
        raise RuntimeError(f"Guard refused landing with exit {result.returncode}")
    value = json.loads(result.stdout)
    if not isinstance(value, dict):
        raise TypeError("Guard result is not an object")
    return value


def run(repository: Path, helper: Path, pr: str, head: str, audit: Path) -> None:
    """Require live readiness and request only the exact user-approved head.

    Parameters
    ----------
    repository : Path
        Checkout of the approved target head, including its policy files.
    helper : Path
        Unchanged shipped ``pr_land.py`` alongside ``pr_watch.py``.
    pr : str
        Fixed PR URL selected by the user-authorized operation.
    head : str
        Approved head SHA; the helper and GitHub CLI both enforce this value.
    audit : Path
        Destination for readiness, plan, request, and terminal observations.

    Notes
    -----
    This driver does not invoke a merge API or construct a merge command. The
    shipped helper performs the sole mutation after fresh readiness checks and
    requires the plan's unchanged readiness-policy digest. Repository policy
    discovery is preserved. A queue is used only when the watcher requires it.
    """
    audit.mkdir(parents=True, exist_ok=True)
    watcher = helper.with_name("pr_watch.py")
    target = f"{repository}={pr}"
    common_watch = [
        sys.executable,
        str(watcher),
        "--target",
        target,
        "--cursor",
        str(audit / "cursor.json"),
        "--observations-file",
        str(audit / "observations.ndjson"),
        "--timeout",
        "180",
        "--interval",
        "10",
        "--max-interval",
        "20",
    ]
    ready = capture(
        common_watch + ["--mode", "until-actionable"], audit / "ready.json", repository
    )
    if ready["state"] == "merged":
        verify_terminal(ready, head)
        return
    if ready["state"] != "ready":
        raise RuntimeError("Live watcher did not report ready")
    target_state = ready["targets"][0]
    queue = target_state["pr"]["isMergeQueueEnabled"]
    mode = "queue" if queue else "auto"
    landing = [
        sys.executable,
        str(helper),
        "--repo",
        str(repository),
        "--pr",
        pr,
        "--head",
        head,
        "--mode",
        mode,
    ]
    if mode == "auto":
        landing += ["--method", "merge"]
    plan = capture(landing, audit / "plan.json", repository)
    if plan["state"] != "confirmation_required" or plan["headSha"] != head:
        raise RuntimeError("Landing plan differs from the approved operation")
    requested = capture(
        landing + ["--policy-digest", plan["readinessPolicyDigest"], "--confirm"],
        audit / "request.json",
        repository,
    )
    if requested["state"] != "landing_requested":
        raise RuntimeError("Landing request was not accepted")
    final = capture(
        common_watch
        + [
            "--mode",
            "until-actionable",
            "--await-merge",
            head,
            "--await-merge-mode",
            mode,
            "--await-merge-since",
            requested["requestedAt"],
        ],
        audit / "terminal.json",
        repository,
    )
    verify_terminal(final, head)


def verify_terminal(snapshot: dict[str, Any], head: str) -> None:
    """Require observed merge of the exact approved head before returning."""
    if snapshot["state"] != "merged":
        raise RuntimeError("Merge has not been observed")
    if snapshot["targets"][0]["pr"]["headSha"] != head:
        raise RuntimeError("Merged head differs from the approved head")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--helper", type=Path, required=True)
    parser.add_argument("--pr", required=True)
    parser.add_argument("--head", required=True)
    parser.add_argument("--audit", type=Path, required=True)
    arguments = parser.parse_args()
    run(
        arguments.repository.resolve(),
        arguments.helper.resolve(),
        arguments.pr,
        arguments.head,
        arguments.audit.resolve(),
    )
