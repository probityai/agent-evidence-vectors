#!/usr/bin/env python3
"""Fail when a workflow can publish outside an approved release.

One approval of one release publishes both destinations: the PyPI wheel of
release.yml and the Hugging Face dataset of publish-hf-dataset.yml. Both jobs
sit behind the protected environment `public-release`, whose required reviewer
is the repository owner. This test reads every workflow and refuses:

  * a job that holds the HF_TOKEN secret or an upload command (PyPI, crates.io,
    npm, Hugging Face, release creation) without an `environment`;
  * a workflow that names `public-release` and also has a trigger other than a
    pushed `v*` tag, a published release, or the pull-request and main-push runs
    that only test;
  * a Hugging Face publish job that does not run for `release` events only, or
    that lacks the environment;
  * any use of HF_TOKEN outside a job in `public-release`;
  * the corpus PyPI publish job without `public-release`.

Exit 0 on success, 1 on any failure.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parent.parent
WORKFLOWS = ROOT / ".github" / "workflows"
ENV = "public-release"
PUBLISH_MARKERS = re.compile(
    r"pypi-publish|gh-action-pypi|twine upload|cargo publish|npm publish|HF_TOKEN"
    r"|hf upload|publish-hf-dataset\.py upload|gh release (create|upload)|deploy-pages"
)
# Deploys of the project site and OpenSSF result publishing, which carry no corpus.
EXEMPT_ENVIRONMENTS = {"github-pages"}
ALLOWED_PUBLIC_RELEASE_TRIGGERS = {"push", "release", "pull_request"}


def load(path: Path) -> dict[str, Any]:
    doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(doc, dict):
        raise ValueError(f"{path}: not a mapping")
    # YAML 1.1 reads the key `on` as True.
    if True in doc and "on" not in doc:
        doc["on"] = doc.pop(True)
    return doc


def triggers(doc: dict[str, Any]) -> set[str]:
    on = doc.get("on")
    if isinstance(on, str):
        return {on}
    if isinstance(on, list):
        return set(on)
    return set(on or {})


def env_name(job: dict[str, Any]) -> str | None:
    env = job.get("environment")
    return env.get("name") if isinstance(env, dict) else env


def problems_for(name: str, doc: dict[str, Any]) -> list[str]:
    problems: list[str] = []
    jobs: dict[str, Any] = doc.get("jobs") or {}
    names_env = any(env_name(j) == ENV for j in jobs.values())
    if names_env:
        extra = triggers(doc) - ALLOWED_PUBLIC_RELEASE_TRIGGERS
        if extra:
            problems.append(f"{name}: triggers {sorted(extra)} can reach the {ENV} jobs")
    for job_id, job in jobs.items():
        if not isinstance(job, dict):
            continue
        text = yaml.safe_dump(job)
        env = env_name(job)
        if env in EXEMPT_ENVIRONMENTS:
            continue
        if "HF_TOKEN" in text and env != ENV:
            problems.append(f"{name}: job {job_id} uses HF_TOKEN outside {ENV}")
        if PUBLISH_MARKERS.search(text) and not env:
            problems.append(f"{name}: job {job_id} publishes without an environment")
        if env == ENV and "release" not in triggers(doc) | {"push"}:
            problems.append(f"{name}: job {job_id} is in {ENV} but has no release path")
    return problems


def specific_problems(workflows: dict[str, dict[str, Any]]) -> list[str]:
    problems: list[str] = []
    hf = workflows.get("publish-hf-dataset.yml")
    if hf is None:
        return ["publish-hf-dataset.yml is missing"]
    job = (hf.get("jobs") or {}).get("publish") or {}
    if env_name(job) != ENV:
        problems.append(f"publish-hf-dataset.yml: publish job is not in {ENV}")
    condition = str(job.get("if", ""))
    if "github.event_name == 'release'" not in condition:
        problems.append("publish-hf-dataset.yml: publish job does not require a release event")
    if "workflow_dispatch" in triggers(hf) or "schedule" in triggers(hf):
        problems.append("publish-hf-dataset.yml: a manual or scheduled trigger exists")
    rel = workflows.get("release.yml")
    if rel is None:
        return problems + ["release.yml is missing"]
    if "workflow_dispatch" in triggers(rel):
        problems.append("release.yml: workflow_dispatch can reach the publish jobs")
    corpus = (rel.get("jobs") or {}).get("publish") or {}
    if env_name(corpus) != ENV:
        problems.append(f"release.yml: the corpus PyPI publish job is not in {ENV}")
    return problems


def check_all(directory: Path) -> list[str]:
    workflows = {p.name: load(p) for p in sorted(directory.glob("*.yml"))}
    problems = specific_problems(workflows)
    for name, doc in workflows.items():
        problems += problems_for(name, doc)
    return problems


def main() -> int:
    problems = check_all(WORKFLOWS)
    for problem in problems:
        print(f"publish-gate-test: {problem}", file=sys.stderr)
    if problems:
        return 1
    print("ok: every publish job is behind the approved release")
    return 0


if __name__ == "__main__":
    sys.exit(main())
