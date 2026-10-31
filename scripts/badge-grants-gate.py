#!/usr/bin/env python3
"""Re-check every Verified by Probity grant against the badge evidence rule.

A badge is granted, never self-declared, and it is re-checked at every release of
the corpus. `docs/badge-grants.json` is the record of grants. This gate reads each
active grant's recorded workflow-provenance evidence and refuses the release when
one no longer meets the rule in `docs/VERIFIED-BADGE.md`.

What it checks, per active grant:

* the job workflow reference is the registered reusable conformance workflow at a
  full commit SHA (never a tag), and that SHA is on the workflow allowlist;
* the allowlist entry was active when the receipt was logged, and has not been
  sunset or revoked in a way that reaches this receipt;
* the run was on a GitHub-hosted runner, from a permitted event, on the
  registered repository (name and id) at its default branch;
* every digest the receipt must bind is present, and the covered members and the
  recorded result are not empty;
* a replay-qualified grant carries the replay record digest and names a
  registered replay environment.

What it does not check: the signature on the receipt. Verifying the keyless
signature, the transparency-log inclusion and the execution bundle belongs to the
badge verifier that ships with the reusable workflow. This gate re-evaluates the
recorded claims against the current allowlist and revocation state, which is what
changes between releases.

Usage: ``python3 scripts/badge-grants-gate.py [--ledger <path>]``.
Exit 0 when every active grant passes (an empty ledger passes), 1 with the
failures, 2 when the ledger cannot be read.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
LEDGER_REL = "docs/badge-grants.json"

SCHEMA = "badge-grants-v1"
BASES = ("applicant-originated", "replay-qualified")
STATUSES = ("active", "withdrawn")
REVOCATION_EFFECTS = ("future-mint", "suspend", "invalidate")

FULL_SHA = re.compile(r"[0-9a-f]{40}")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
REPO_NAME = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")

DIGEST_FIELDS = (
    "receipt_digest",
    "execution_bundle_digest",
    "candidate_closure_digest",
    "corpus_digest",
    "expectation_digest",
    "release_manifest_digest",
)
EVIDENCE_FIELDS = (
    "job_workflow_ref",
    "workflow_ref",
    "runner_environment",
    "event_name",
    "ref",
    "sha",
    "run_id",
    "run_attempt",
    "repository",
    "repository_id",
    "issuer",
    "integrated_time",
    "result",
    "covered_members",
) + DIGEST_FIELDS


def _time(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else None


def _policy_errors(ledger: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if ledger.get("schema") != SCHEMA:
        errors.append(f"schema must be {SCHEMA!r}")
    policy = ledger.get("policy")
    if not isinstance(policy, dict):
        return errors + ["policy must be an object"]
    for key in ("events", "runner_environment", "issuer"):
        if not policy.get(key):
            errors.append(f"policy.{key} is missing")
    if not isinstance(policy.get("events"), list):
        errors.append("policy.events must be a list of event names")
    for key in ("workflows", "replay_environments", "grants"):
        if not isinstance(ledger.get(key), list):
            errors.append(f"{key} must be a list")
    return errors


def _workflow_entry_errors(entry: Any, index: int) -> list[str]:
    where = f"workflows[{index}]"
    if not isinstance(entry, dict):
        return [f"{where} must be an object"]
    errors: list[str] = []
    if not FULL_SHA.fullmatch(str(entry.get("sha", ""))):
        errors.append(f"{where}.sha must be a full lowercase commit SHA")
    if _time(entry.get("activated")) is None:
        errors.append(f"{where}.activated must be a timestamp with a zone")
    sunset = entry.get("sunset")
    if sunset is not None and _time(sunset) is None:
        errors.append(f"{where}.sunset must be null or a timestamp with a zone")
    revocation = entry.get("revocation")
    if revocation is not None:
        effect = revocation.get("effect") if isinstance(revocation, dict) else None
        if effect not in REVOCATION_EFFECTS:
            errors.append(f"{where}.revocation.effect must be one of {REVOCATION_EFFECTS}")
        elif effect == "invalidate" and _time(revocation.get("since")) is None:
            errors.append(f"{where}.revocation.since is required for effect invalidate")
    return errors


def _revocation_error(entry: dict[str, Any], logged: datetime) -> str | None:
    revocation = entry.get("revocation")
    if not revocation:
        return None
    effect = revocation["effect"]
    if effect == "suspend":
        return "its workflow SHA is suspended, so later revalidation is refused"
    if effect == "invalidate":
        since = _time(revocation["since"])
        if since is not None and logged >= since:
            return "its workflow SHA was revoked from a time that reaches this receipt"
    return None


def _workflow_errors(evidence: dict[str, Any], ledger: dict[str, Any]) -> list[str]:
    reusable = ledger["policy"].get("reusable_workflow")
    if not reusable:
        return ["no reusable workflow is registered in the policy, so no grant can hold"]
    ref = str(evidence["job_workflow_ref"])
    path, _, sha = ref.rpartition("@")
    if path != reusable:
        return [f"job_workflow_ref names {path!r}, not the registered workflow {reusable!r}"]
    if not FULL_SHA.fullmatch(sha):
        return ["job_workflow_ref must end in @ and a full commit SHA, never a tag or branch"]
    entries = [e for e in ledger["workflows"] if isinstance(e, dict) and e.get("sha") == sha]
    if not entries:
        return [f"workflow SHA {sha} is not on the allowlist"]
    entry = entries[0]
    logged, activated = _time(evidence["integrated_time"]), _time(entry.get("activated"))
    if logged is None:
        return ["integrated_time must be a timestamp with a zone"]
    errors = []
    if activated is not None and logged < activated:
        errors.append("the receipt was logged before its workflow SHA was activated")
    sunset = _time(entry.get("sunset"))
    if sunset is not None and logged > sunset:
        errors.append("the receipt was logged after its workflow SHA was sunset")
    revoked = _revocation_error(entry, logged)
    if revoked:
        errors.append(revoked)
    return errors


def _run_errors(
    grant: dict[str, Any], evidence: dict[str, Any], policy: dict[str, Any]
) -> list[str]:
    errors = []
    if evidence["runner_environment"] != policy["runner_environment"]:
        errors.append(f"runner_environment must be {policy['runner_environment']!r}")
    if evidence["event_name"] not in policy["events"]:
        errors.append(f"event {evidence['event_name']!r} is not a permitted event")
    if evidence["issuer"] != policy["issuer"]:
        errors.append("issuer does not match the policy")
    if evidence["repository"] != grant.get("repository"):
        errors.append("evidence.repository does not match the registered repository")
    if evidence["repository_id"] != grant.get("repository_id"):
        errors.append("evidence.repository_id does not match the registered repository_id")
    if evidence["ref"] != f"refs/heads/{grant.get('default_branch')}":
        errors.append("ref is not the registered default branch")
    return errors + _identity_errors(grant, evidence)


def _identity_errors(grant: dict[str, Any], evidence: dict[str, Any]) -> list[str]:
    errors = []
    if not str(evidence["workflow_ref"]).startswith(
        f"{grant.get('repository')}/.github/workflows/"
    ):
        errors.append("workflow_ref is not a workflow of the registered repository")
    if not FULL_SHA.fullmatch(str(evidence["sha"])):
        errors.append("sha must be a full lowercase commit SHA")
    for key in ("run_id", "run_attempt", "repository_id"):
        value = evidence[key]
        if isinstance(value, bool) or not isinstance(value, int) or value < 1:
            errors.append(f"{key} must be a positive integer")
    if evidence["result"] != "pass":
        errors.append("recorded result must be pass")
    members = evidence["covered_members"]
    if not isinstance(members, list) or not members:
        errors.append("covered_members must be a non-empty list")
    return errors


def _basis_errors(
    grant: dict[str, Any], evidence: dict[str, Any], ledger: dict[str, Any]
) -> list[str]:
    if grant.get("basis") == "replay-qualified":
        errors = []
        if not DIGEST.fullmatch(str(evidence.get("replay_record_digest", ""))):
            errors.append("a replay-qualified grant needs evidence.replay_record_digest")
        if evidence.get("replay_environment") not in ledger["replay_environments"]:
            errors.append("evidence.replay_environment is not a registered replay environment")
        return errors
    return []


def grant_errors(grant: Any, ledger: dict[str, Any]) -> list[str]:
    """Every reason an active grant no longer meets the evidence rule."""
    if not isinstance(grant, dict):
        return ["grant must be an object"]
    errors: list[str] = []
    if not REPO_NAME.fullmatch(str(grant.get("repository", ""))):
        errors.append("repository must be owner/name")
    for key in ("project", "default_branch", "granted", "consent_url"):
        if not grant.get(key):
            errors.append(f"{key} is missing")
    if grant.get("basis") not in BASES:
        errors.append(f"basis must be one of {BASES}")
    evidence = grant.get("evidence")
    if not isinstance(evidence, dict):
        return errors + ["evidence must be an object"]
    missing = [key for key in EVIDENCE_FIELDS if key not in evidence]
    if missing:
        return errors + [f"evidence is missing {', '.join(missing)}"]
    errors += [
        f"{key} is not a sha256 digest"
        for key in DIGEST_FIELDS
        if not DIGEST.fullmatch(str(evidence[key]))
    ]
    errors += _run_errors(grant, evidence, ledger["policy"])
    errors += _workflow_errors(evidence, ledger)
    errors += _basis_errors(grant, evidence, ledger)
    return errors


def _withdrawn_errors(grant: dict[str, Any]) -> list[str]:
    return [
        f"a withdrawn grant needs {key}" for key in ("withdrawn", "reason") if not grant.get(key)
    ]


def check(ledger: Any) -> list[str]:
    """All failures in a parsed ledger, each prefixed with the grant it concerns."""
    if not isinstance(ledger, dict):
        return ["the ledger must be a JSON object"]
    errors = _policy_errors(ledger)
    if errors:
        return errors
    for index, entry in enumerate(ledger["workflows"]):
        errors += _workflow_entry_errors(entry, index)
    if errors:
        return errors
    seen: set[str] = set()
    for grant in ledger["grants"]:
        name = str(grant.get("repository", "?")) if isinstance(grant, dict) else "?"
        status = grant.get("status") if isinstance(grant, dict) else None
        if status not in STATUSES:
            errors.append(f"{name}: status must be one of {STATUSES}")
            continue
        if name in seen:
            errors.append(f"{name}: listed twice")
        seen.add(name)
        found = _withdrawn_errors(grant) if status == "withdrawn" else grant_errors(grant, ledger)
        errors += [f"{name}: {message}" for message in found]
    return errors


def main(argv: list[str] | None = None) -> int:
    summary = (__doc__ or "").strip().splitlines()
    parser = argparse.ArgumentParser(description=summary[0] if summary else None)
    parser.add_argument("--ledger", type=Path, default=REPO_ROOT / LEDGER_REL)
    args = parser.parse_args(argv)
    try:
        ledger = json.loads(args.ledger.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        print(f"badge-grants-gate: cannot read {args.ledger}: {exc}", file=sys.stderr)
        return 2
    errors = check(ledger)
    if errors:
        for message in errors:
            print(f"badge-grants-gate: {message}", file=sys.stderr)
        return 1
    active = sum(1 for g in ledger["grants"] if g.get("status") == "active")
    print(f"badge-grants-gate: {active} active grant(s) meet the evidence rule")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
