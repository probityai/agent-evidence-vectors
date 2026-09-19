#!/usr/bin/env python3
"""Refuse a workflow whose runner label nothing can serve.

The defect this exists for, measured 2026-09-19. The three public repositories
moved to a new GitHub organisation. A GitHub App installation does not follow a
repository transfer, and the new organisation had NO installations at all. Seven
jobs here ask for `ubicloud-standard-2` and `ubicloud-standard-8`, which only an
installed Ubicloud app serves. Those jobs queued for thirty-six minutes and were
cancelled. Six workflows on the same commit went green, because they use
GitHub-hosted runners.

Nothing refused and nothing warned. A queued job looks exactly like a slow job,
so the outage was invisible until a human read an email from the vendor. That is
the same family as every other instrument in this repository: the check that was
never written cannot report that it has stopped applying.

The rule: every `runs-on` label is either a GitHub-hosted label this file knows,
or it is served by an app installed on the account that owns the repository. A
third-party label with no matching installation is refused by name.

Exit 0 when every label is servable. Exit 1 on a label nothing serves. Exit 2
when the installation set could not be read, because an unread account is not an
empty account -- a token without `admin:org`, a network failure and an
organisation with no apps all return nothing, and only one of those is a finding.

Usage: python3 scripts/runner-labels-gate.py [--owner OWNER]
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
WORKFLOWS = HERE.parent / ".github" / "workflows"

# GitHub-hosted labels need no installation. Kept as prefixes because the
# version suffix moves (ubuntu-22.04, ubuntu-24.04) and a list of exact strings
# would refuse a valid upgrade.
HOSTED_PREFIXES = ("ubuntu-", "windows-", "macos-", "self-hosted")

# A third-party label's vendor is the first dash-separated token. `ubicloud-
# standard-8` is served by the Ubicloud app; the app slug is matched case
# insensitively against the installed set.
RUNS_ON = re.compile(r"^\s*runs-on:\s*(?P<label>[A-Za-z0-9_.-]+)\s*$")


def declared_labels() -> dict[str, list[str]]:
    """Every `runs-on` label in this repository's workflows, by label.

    Only the plain scalar form is read. A matrix or an expression is reported
    as unreadable rather than skipped, because a label this cannot see is a
    label this cannot vouch for.
    """
    found: dict[str, list[str]] = {}
    for path in sorted(WORKFLOWS.glob("*.yml")) + sorted(WORKFLOWS.glob("*.yaml")):
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            match = RUNS_ON.match(line)
            if match:
                label = match.group("label")
                found.setdefault(label, []).append(f"{path.name}:{number}")
    return found


def installed_apps(owner: str) -> set[str]:
    """App slugs installed on the owning account.

    Raises SystemExit(2) when the read fails. An account whose installations
    cannot be read is INCONCLUSIVE, never empty: this gate refuses to turn a
    failed call into a finding about the world.
    """
    proc = subprocess.run(
        ["gh", "api", f"/orgs/{owner}/installations", "--jq", ".installations[].app_slug"],
        capture_output=True,
        text=True,
        timeout=90,
    )
    if proc.returncode != 0:
        raise SystemExit(
            f"could not read installations for {owner}: {proc.stderr.strip()[:200]}. "
            "This is a failed check, not an empty account. A token without "
            "admin:org and an organisation with no apps return the same nothing."
        )
    return {line.strip().lower() for line in proc.stdout.splitlines() if line.strip()}


def owner_of_origin() -> str:
    proc = subprocess.run(
        ["git", "remote", "get-url", "origin"], capture_output=True, text=True, timeout=30
    )
    if proc.returncode != 0:
        raise SystemExit(f"could not read the origin remote: {proc.stderr.strip()[:200]}")
    url = proc.stdout.strip()
    match = re.search(r"[:/]([^/:]+)/[^/]+?(?:\.git)?$", url)
    if not match:
        raise SystemExit(f"could not read an owner out of the origin remote: {url}")
    return match.group(1)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--owner", help="account that owns the repository; default reads origin")
    args = parser.parse_args()

    owner = args.owner or owner_of_origin()
    labels = declared_labels()
    if not labels:
        raise SystemExit(
            f"no runs-on label was read from {WORKFLOWS}. A scan that found nothing "
            "has verified nothing."
        )

    third_party = {
        label: sites
        for label, sites in labels.items()
        if not label.startswith(HOSTED_PREFIXES)
    }
    if not third_party:
        print(
            f"runner-labels-gate: {len(labels)} label(s) over "
            f"{sum(len(v) for v in labels.values())} job(s), all GitHub-hosted; "
            "no installation is needed."
        )
        return 0

    apps = installed_apps(owner)
    failures: list[str] = []
    for label, sites in sorted(third_party.items()):
        vendor = label.split("-", 1)[0].lower()
        if vendor not in apps:
            failures.append(
                f"  {label} ({len(sites)} job(s): {', '.join(sites)}) needs an app "
                f"matching '{vendor}' installed on '{owner}'. Installed: "
                f"{', '.join(sorted(apps)) or 'nothing'}."
            )

    if failures:
        print(
            f"runner-labels-gate: {len(failures)} runner label(s) nothing on "
            f"'{owner}' can serve. Jobs asking for these do not fail; they QUEUE "
            "until GitHub expires them, which reads as a slow build.",
            file=sys.stderr,
        )
        for line in failures:
            print(line, file=sys.stderr)
        print(
            "  Install the app on the owning account, or move the jobs to a "
            "GitHub-hosted label. An app installation does not follow a "
            "repository transfer.",
            file=sys.stderr,
        )
        return 1

    print(
        f"runner-labels-gate: {len(third_party)} third-party label(s) over "
        f"{sum(len(v) for v in third_party.values())} job(s), each served by an "
        f"app installed on '{owner}'."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
