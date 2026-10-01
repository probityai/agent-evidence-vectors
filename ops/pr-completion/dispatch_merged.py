#!/usr/bin/env python3
"""Dispatch native functional CI only after the exact approved merge is observed."""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence


LOGGER = logging.getLogger(__name__)
JsonObject = dict[str, Any]
READ_API_VERSION = "2022-11-28"
DISPATCH_API_VERSION = "2026-03-10"


class ValidationError(RuntimeError):
    """A merge or dispatch identity differs from the approved operation."""


class GitHubApi:
    """Read GitHub state and dispatch workflows with the runner's existing token."""

    def request(self, endpoint: str, payload: JsonObject | None = None) -> JsonObject:
        """Execute a supported GitHub CLI API request and require an object.

        Parameters
        ----------
        endpoint : str
            Repository REST endpoint without a hostname or leading slash.
        payload : dict[str, Any], optional
            JSON body for a workflow-dispatch POST; omitted for a GET.

        Returns
        -------
        dict[str, Any]
            Decoded response using the stable read schema or new dispatch schema.

        Raises
        ------
        ValidationError
            If the API refuses the request or returns a non-object body.

        Notes
        -----
        Credentials stay in ``GH_TOKEN``. They never enter the argument vector,
        logs, or retained evidence. :func:`dispatch_workflow` is the sole caller
        that supplies a POST body; no merge API is used here. GET requests pin
        2022-11-28 because 2026-03-10 removes PR ``merge_commit_sha``.
        Dispatch POST alone uses 2026-03-10 for its run ID.
        """
        version = READ_API_VERSION if payload is None else DISPATCH_API_VERSION
        command = [
            "gh", "api", "-H", "Accept: application/vnd.github+json",
            "-H", f"X-GitHub-Api-Version: {version}", endpoint,
        ]
        options: JsonObject = {"text": True, "capture_output": True, "check": False}
        if payload is not None:
            command.extend(["--method", "POST", "--input", "-"])
            options["input"] = json.dumps(payload)
        result = subprocess.run(command, **options)
        if result.returncode:
            raise ValidationError(f"GitHub request failed for {endpoint}: {result.stderr.strip()}")
        response = json.loads(result.stdout)
        if not isinstance(response, dict):
            raise ValidationError(f"GitHub returned a non-object for {endpoint}")
        return response


@dataclass(frozen=True, slots=True)
class MergedTarget:
    """The approved PR head, observed main merge, and their identical tree."""

    repository: str
    pr_number: int
    approved_head: str
    merge_sha: str
    tree_sha: str


def require_equal(actual: object, expected: object, description: str) -> None:
    """Refuse an identity mismatch with an explicit expected and actual value."""
    if actual != expected:
        raise ValidationError(f"{description}: expected {expected!r}; found {actual!r}")


def save_json(path: Path, payload: JsonObject) -> None:
    """Atomically retain an API observation or dispatch manifest as UTF-8 JSON."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)


def validate_merge(
    api: GitHubApi, repository: str, pr_number: int, approved_head: str, audit: Path
) -> MergedTarget:
    """Require an observed owned merge whose current main tree is approved.

    Parameters
    ----------
    api : GitHubApi
        Authenticated runner client; only GET requests are made by this function.
    repository : str
        Fixed owned repository in ``owner/name`` form.
    pr_number : int
        Pull request already observed as merged by unchanged landing guards.
    approved_head : str
        Exact head authorized by the fixed landing workflow.
    audit : pathlib.Path
        Directory for raw PR, ref, and commit observations.

    Returns
    -------
    MergedTarget
        Verified identities used by :func:`dispatch_workflow`.

    Raises
    ------
    ValidationError
        If the PR, main SHA, approved tree, or merge tree differs from the
        authorized operation. A later main commit requires a fresh operation.
    """
    pr = api.request(f"repos/{repository}/pulls/{pr_number}")
    save_json(audit / "pr.json", pr)
    require_equal(pr["merged"], True, "PR merged state")
    require_equal(pr["state"], "closed", "PR terminal state")
    require_equal(pr["head"]["sha"], approved_head, "Merged PR head")
    require_equal(pr["head"]["repo"]["full_name"], repository, "Approved head repository")
    require_equal(pr["base"]["repo"]["full_name"], repository, "PR base repository")
    require_equal(pr["base"]["ref"], "main", "PR base branch")
    merge_sha = checked_sha(pr["merge_commit_sha"])
    approved = api.request(f"repos/{repository}/git/commits/{approved_head}")
    merged = api.request(f"repos/{repository}/git/commits/{merge_sha}")
    save_json(audit / "approved-commit.json", approved)
    save_json(audit / "merge-commit.json", merged)
    tree_sha = checked_sha(approved["tree"]["sha"])
    require_equal(merged["tree"]["sha"], tree_sha, "Main tree versus approved head tree")
    target = MergedTarget(repository, pr_number, approved_head, merge_sha, tree_sha)
    validate_main(api, target, audit)
    LOGGER.info("Observed approved head %s merged as main %s", approved_head, merge_sha)
    return target


def validate_main(api: GitHubApi, target: MergedTarget, audit: Path) -> None:
    """Require main still names the observed merge before each dispatch."""
    main = api.request(f"repos/{target.repository}/git/ref/heads/main")
    save_json(audit / "main-ref.json", main)
    require_equal(main["object"]["sha"], target.merge_sha, "Current main commit")


def validate_native_run(run: JsonObject, target: MergedTarget, workflow: str) -> None:
    """Require the real native run to test the observed merge on main."""
    expected = {
        "head_sha": target.merge_sha,
        "head_branch": "main",
        "event": "workflow_dispatch",
        "path": f".github/workflows/{workflow}",
    }
    for field, value in expected.items():
        require_equal(run.get(field), value, f"Native {workflow} run {field}")


def dispatch_workflow(
    api: GitHubApi, target: MergedTarget, workflow: str, audit: Path
) -> JsonObject:
    """Dispatch unchanged native jobs and verify their exact returned run ID.

    Parameters
    ----------
    api : GitHubApi
        Runner client authorized for Actions dispatch in the owned repository.
    target : MergedTarget
        Identity returned by :func:`validate_merge`.
    workflow : str
        Existing workflow filename with ``workflow_dispatch`` on default main.
    audit : pathlib.Path
        Destination for the dispatch response and observed native run.

    Returns
    -------
    dict[str, Any]
        Native run ID, URL, target SHA, and observed status/conclusion. A queued
        or running workflow is evidence of dispatch, not evidence of passing CI.

    Raises
    ------
    ValidationError
        If main moved, dispatch lacks a run ID, or native execution identity
        differs. Raw returned observations remain in ``audit`` on failure.
    """
    validate_main(api, target, audit)
    response = api.request(
        f"repos/{target.repository}/actions/workflows/{workflow}/dispatches",
        {"ref": "main"},
    )
    save_json(audit / f"dispatch-{workflow}.json", response)
    run_id = response.get("workflow_run_id")
    if type(run_id) is not int or run_id <= 0:
        raise ValidationError(f"Native {workflow} dispatch returned no positive integer run ID")
    run = api.request(f"repos/{target.repository}/actions/runs/{run_id}")
    save_json(audit / f"run-{workflow}.json", run)
    validate_native_run(run, target, workflow)
    LOGGER.info("Dispatched %s on %s: %s", workflow, target.merge_sha, run["html_url"])
    return {
        "workflow": workflow, "run_id": run_id, "run_url": run["html_url"],
        "head_sha": run["head_sha"], "status_at_dispatch": run["status"],
        "conclusion_at_dispatch": run["conclusion"],
    }


def checked_sha(value: str) -> str:
    """Accept only a complete lowercase Git commit or tree SHA."""
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{40}", value) is None:
        raise ValidationError(f"Invalid complete Git SHA: {value!r}")
    return value


def checked_workflow(value: str) -> str:
    """Accept a workflow basename, excluding directories and shell metacharacters."""
    if re.fullmatch(r"[A-Za-z0-9_.-]+\.ya?ml", value) is None:
        raise argparse.ArgumentTypeError(f"Invalid workflow filename: {value!r}")
    return value


def parser() -> argparse.ArgumentParser:
    """Build the fixed-identity command-line interface used by ops launchers."""
    arguments = argparse.ArgumentParser(description=__doc__)
    arguments.add_argument("--repository", required=True)
    arguments.add_argument("--pr-number", type=int, required=True)
    arguments.add_argument("--approved-head", type=checked_sha, required=True)
    arguments.add_argument("--expected-merge", type=checked_sha)
    arguments.add_argument("--workflow", type=checked_workflow, action="append", required=True)
    arguments.add_argument("--audit", type=Path, required=True)
    return arguments


def run(arguments: argparse.Namespace, api: GitHubApi) -> JsonObject:
    """Validate the merge and retain each real native dispatch incrementally."""
    target = validate_merge(
        api, arguments.repository, arguments.pr_number, arguments.approved_head, arguments.audit
    )
    expected_merge = getattr(arguments, "expected_merge", None)
    if expected_merge is not None:
        require_equal(target.merge_sha, expected_merge, "Pinned recovery merge commit")
    evidence: JsonObject = {
        "repository": target.repository, "pr_number": target.pr_number,
        "approved_head": target.approved_head, "target_merge_sha": target.merge_sha,
        "approved_tree_sha": target.tree_sha, "launcher_sha": os.getenv("GITHUB_SHA"),
        "launcher_run_id": os.getenv("GITHUB_RUN_ID"), "native_runs": [],
    }
    manifest = arguments.audit / "native-dispatch-evidence.json"
    save_json(manifest, evidence)
    for workflow in dict.fromkeys(arguments.workflow):
        evidence["native_runs"].append(dispatch_workflow(api, target, workflow, arguments.audit))
        save_json(manifest, evidence)
    return evidence


def main(argv: Sequence[str] | None = None) -> int:
    """Emit dispatch evidence; report validation failures without changing merge state."""
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    arguments = parser().parse_args(argv)
    try:
        evidence = run(arguments, GitHubApi())
    except (ValidationError, KeyError, json.JSONDecodeError) as error:
        LOGGER.error("Post-merge dispatch refused: %s", error)
        save_json(arguments.audit / "dispatch-error.json", {"error": str(error)})
        return 1
    print(json.dumps(evidence, indent=2, sort_keys=True), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
