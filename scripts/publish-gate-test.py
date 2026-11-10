#!/usr/bin/env python3
"""Fail when a workflow can publish outside an approved release.

One approval of one tagged release publishes both destinations: the PyPI wheel
and the Hugging Face dataset, in the single `publish` job of release.yml, which
runs in the protected environment `public-release` (required reviewer: the
repository owner). This test reads every workflow file (`*.yml` and `*.yaml`)
and refuses:

  * a job that publishes (an upload command, `id-token: write` at job or
    workflow level, or the HF token) without a literal, named environment;
  * any secret reference that is not a plain `secrets.NAME`, so a computed
    name, `toJSON(secrets)` or `secrets: inherit` cannot hide the token;
  * `secrets.HF_TOKEN` anywhere except release.yml's `publish` job;
  * `environment: public-release` on any job but that one;
  * a release.yml `publish` job whose condition is not exactly the tag-push
    condition, whose push trigger is anything but `tags: ['v*']`, or that
    carries a manual trigger;
  * a publish_hf_dataset job in ci.yml that has a secret, an environment or an
    upload, or a ci.yml with a trigger other than the test runs.

Exit 0 on success, 1 on any failure.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Any

import yaml

_LOADER = getattr(yaml, "CSafeLoader", yaml.SafeLoader)
ROOT = Path(__file__).resolve().parent.parent
WORKFLOWS = ROOT / ".github" / "workflows"
ENV = "public-release"
TOKEN_JOB = ("release.yml", "publish")
PUBLISH_IF = "${{ github.event_name != 'release' && startsWith(github.ref, 'refs/tags/v') }}"
PUBLISH_MARKERS = re.compile(
    r"pypi-publish|gh-action-pypi|twine upload|uv publish|hatch publish|poetry publish"
    r"|maturin publish|upload\.pypi\.org|cargo publish|npm publish|HF_TOKEN|hf upload"
    r"|huggingface_hub|HfApi|upload_folder|publish-hf-dataset\.py upload"
    r"|gh release (create|upload)|deploy-pages|id-token:\s*write"
)
DYNAMIC_SECRET = re.compile(
    r"secrets\s*\[|toJSON\(\s*secrets|fromJSON\(\s*secrets|secrets:\s*inherit"
)
NAMED_SECRET = re.compile(r"secrets\.([A-Za-z_][A-Za-z0-9_]*)")
# Jobs that publish and are not the corpus release: the project site and OpenSSF
# result publishing. They may name only these environments and read no secret.
# release.yml's package jobs publish one unit to its registry on a release event, in
# their own environments, through trusted publishing; they never see HF_TOKEN.
UNIT_ENVIRONMENTS = {"crates-io", "npm", "pypi"}
OIDC_WORKFLOWS = {"pages.yml"}
EXACT_EXEMPT = {("pages.yml", "deploy"): "github-pages", ("scorecard.yml", "analysis"): None}
# A reusable workflow runs in the CALLER's repository, so the OIDC token its jobs ask for
# names the caller and can publish nothing of ours. The conformance workflow asks for one
# only to get a signing certificate. Its jobs may hold `id-token: write` when the file is
# callable only through workflow_call and the job has no environment, no secret and no
# other way to publish.
REUSABLE_OIDC = {"conformance.yml": {"pin", "sign"}}
# ci.yml is the one workflow that tests every pull request, so it carries the test
# triggers only: a release, tag or deployment trigger would let it publish.
TEST_TRIGGERS = {"pull_request", "push", "merge_group", "schedule", "workflow_dispatch"}
HF_JOB = "publish_hf_dataset"


def load(path: Path) -> dict[str, Any]:
    doc = yaml.load(path.read_text(encoding="utf-8"), Loader=_LOADER)  # noqa: S506
    if not isinstance(doc, dict):
        raise ValueError(f"{path}: not a mapping")
    # YAML 1.1 reads the key `on` as True.
    if True in doc and "on" not in doc:
        doc["on"] = doc.pop(True)
    return doc


def triggers(doc: dict[str, Any]) -> dict[str, Any]:
    on = doc.get("on")
    if isinstance(on, str):
        return {on: None}
    if isinstance(on, list):
        return {k: None for k in on}
    return dict(on or {})


def env_name(job: dict[str, Any]) -> str | None:
    env = job.get("environment")
    return env.get("name") if isinstance(env, dict) else env


def dump(obj: Any) -> str:
    return yaml.safe_dump(obj)


def reusable_oidc_publishes(doc: dict[str, Any], job: dict[str, Any], env: str | None) -> bool:
    """True unless this is a signing-only job of a workflow callable only as a reusable one."""
    others = PUBLISH_MARKERS.sub(
        lambda m: "" if m.group(0).startswith("id-token") else m.group(0), dump(job)
    )
    text = dump(job)
    return (
        set(triggers(doc)) != {"workflow_call"}
        or env is not None
        or bool(NAMED_SECRET.search(text))
        or bool(PUBLISH_MARKERS.search(others))
    )


def job_problems(name: str, doc: dict[str, Any], job_id: str, job: dict[str, Any]) -> list[str]:
    where = f"{name}: job {job_id}"
    env = env_name(job)
    text = dump(job) + dump(doc.get("env"))
    problems = []
    if env is not None and (not isinstance(env, str) or "${{" in env):
        problems.append(f"{where} has a computed environment")
    if env == ENV and (name, job_id) != TOKEN_JOB:
        problems.append(f"{where} uses {ENV}; only {TOKEN_JOB[0]}:{TOKEN_JOB[1]} may")
    publishes = bool(PUBLISH_MARKERS.search(dump(job)))
    if job_id in REUSABLE_OIDC.get(name, set()):
        publishes = reusable_oidc_publishes(doc, job, env)
    if (name, job_id) in EXACT_EXEMPT:
        if env != EXACT_EXEMPT[(name, job_id)] or NAMED_SECRET.search(dump(job)):
            problems.append(f"{where} left its exempt shape")
    elif publishes and (name, job_id) != TOKEN_JOB:
        if name == "release.yml" and env in UNIT_ENVIRONMENTS:
            if "HF_TOKEN" in text or "id-token" not in text:
                problems.append(f"{where} is not a plain registry publish")
        else:
            problems.append(f"{where} publishes outside {TOKEN_JOB[0]}:{TOKEN_JOB[1]}")
    if "HF_TOKEN" in text and (name, job_id) != TOKEN_JOB:
        problems.append(f"{where} reaches HF_TOKEN")
    return problems


def check_release(doc: dict[str, Any]) -> list[str]:
    problems = []
    trig = triggers(doc)
    if set(trig) - {"push", "release"}:
        problems.append(f"release.yml: triggers {sorted(set(trig) - {'push', 'release'})}")
    if trig.get("push") != {"tags": ["v*"]}:
        problems.append("release.yml: the push trigger is not exactly tags ['v*']")
    job = (doc.get("jobs") or {}).get("publish") or {}
    if env_name(job) != ENV:
        problems.append(f"release.yml: publish is not in {ENV}")
    if job.get("if") != PUBLISH_IF:
        problems.append("release.yml: publish has a condition other than the tag push")
    if "HF_TOKEN" not in dump(job):
        problems.append("release.yml: publish does not upload the dataset")
    return problems


def check_hf(ci: dict[str, Any]) -> list[str]:
    """The dataset build is tested by a job of ci.yml; that job holds no way to publish.

    It was a workflow of its own (publish-hf-dataset.yml). Folding it into ci.yml keeps
    the guarantee exact when it is read per job: the job holds no secret, environment
    or upload, and the workflow it lives in has no trigger beyond the test runs.
    """
    problems = []
    if set(triggers(ci)) - TEST_TRIGGERS:
        problems.append("ci.yml: a trigger other than the test runs")
    jobs = {k: v for k, v in (ci.get("jobs") or {}).items() if k == HF_JOB}
    if not jobs:
        return [*problems, f"ci.yml: the {HF_JOB} job is missing"]
    text = dump(jobs) + dump(ci.get("env")) + dump(ci.get("permissions"))
    if (
        "secrets" in text
        or ENV in text
        or "environment" in text
        or "upload" in text.replace("upload\n", "")
    ):
        problems.append(f"ci.yml: {HF_JOB} holds a secret, an environment or an upload")
    return problems


def check_all(directory: Path) -> list[str]:
    files = sorted([*directory.glob("*.yml"), *directory.glob("*.yaml")])
    workflows = {p.name: load(p) for p in files}
    problems: list[str] = []
    if "release.yml" not in workflows or "ci.yml" not in workflows:
        return ["release.yml or ci.yml is missing"]
    problems += check_release(workflows["release.yml"])
    problems += check_hf(workflows["ci.yml"])
    for name, doc in workflows.items():
        text = dump(doc)
        if DYNAMIC_SECRET.search(text):
            problems.append(f"{name}: a computed secret reference")
        if name != TOKEN_JOB[0] and "HF_TOKEN" in text:
            problems.append(f"{name}: names HF_TOKEN")
        if "id-token" in dump(doc.get("permissions")) and name not in OIDC_WORKFLOWS:
            problems.append(f"{name}: workflow-level id-token")
        for job_id, job in (doc.get("jobs") or {}).items():
            if isinstance(job, dict):
                problems += job_problems(name, doc, job_id, job)
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
