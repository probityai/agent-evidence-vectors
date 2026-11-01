#!/usr/bin/env python3
"""Five checks that say whether a field of predicates is usable end to end.

A field is a set of predicate types, the corpus that exercises them and the
verifier that judges the corpus (release/field-readiness.toml names them). The
field is ready when each of these holds, read from the live services and the
release itself rather than from any file that states it:

  1. identifier         every predicate type URI answers 200 with its own page
  2. corpus-released    the latest release's signed CORPUS-DIGESTS.txt lists the
                        field's corpus, so a pin to that tag replays it
  3. verifier-released  the reference verifier pinned by that tag's Action
                        (action-reference-requirements.txt) judges every member
                        of that tag's corpus as declared: N of N, N above zero
  4. outside-ci         a workflow on the default branch of a repository outside
                        this organisation runs this repository's Action or
                        package against the corpus, and its last run passed
  5. adopter-record     a record held by an adopter names the field. Such
                        records are not public, so this repository does not read
                        them: the check is NOT-READ unless --records names a file

Each check ends in one of four states. GREEN and RED are findings: the read ran
and returned the answer. INCONCLUSIVE means the read did not complete (a network
error, an HTTP status other than the one asked about, a tool that did not
start), and it is never counted as either finding. NOT-READ means the check
needs input this run was not given.

    python3 scripts/field-readiness.py restart
    python3 scripts/field-readiness.py restart --json
    python3 scripts/field-readiness.py restart --require-green 5 --records held.json

Exit 0 when every check reached a finding (or NOT-READ) and the --require-green
floor, if given, is met; 1 when the floor is not met; 2 when any check was
INCONCLUSIVE, because then the count says nothing.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import re
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
CONFIG = ROOT / "release" / "field-readiness.toml"
API = "https://api.github.com"
TIMEOUT = 30

GREEN, RED, INCONCLUSIVE, NOT_READ = "GREEN", "RED", "INCONCLUSIVE", "NOT-READ"

# The tally the Action's reference stage computes, run inside the pinned
# reference verifier's environment against a tree extracted from the tag.
TALLY = """
import importlib.util, json, sys
from pathlib import Path
root = Path(sys.argv[1]); corpus = root / sys.argv[2]
spec = importlib.util.spec_from_file_location("stage", root / "scripts/action-reference-stage.py")
stage = importlib.util.module_from_spec(spec); spec.loader.exec_module(stage)
entries = json.loads((corpus / "MANIFEST.json").read_text(encoding="utf-8")).get("vectors", [])
checked, total, notes = stage.tally(entries, corpus, stage.load_crosscheck())
print(json.dumps({"checked": checked, "total": total, "notes": notes[:5]}))
"""
TAG_PATHS = (
    "scripts/action-reference-stage.py",
    "vectors-done-receipt",
    "action-reference-requirements.txt",
)


class ReadFailed(Exception):
    """A read that did not complete; the caller reports INCONCLUSIVE."""


@dataclass
class Check:
    number: int
    name: str
    status: str
    detail: str


Fetch = Callable[[str], tuple[int, bytes]]


def fetch(url: str) -> tuple[int, bytes]:
    """GET a URL. Returns (status, body) for any HTTP answer; raises ReadFailed otherwise."""
    headers = {"User-Agent": "field-readiness"}
    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if token and url.startswith(API):
        headers["Authorization"] = f"Bearer {token}"
        headers["Accept"] = "application/vnd.github+json"
    request = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as error:
        return error.code, error.read()
    except (urllib.error.URLError, TimeoutError, OSError) as error:
        raise ReadFailed(f"{url}: {error}") from error


def fetch_json(get: Fetch, url: str) -> Any:
    status, body = get(url)
    if status != 200:
        raise ReadFailed(f"{url} answered {status}")
    return json.loads(body)


def check_identifier(config: dict[str, Any], field: dict[str, Any], get: Fetch) -> Check:
    missing, failed = [], []
    for name in field["predicates"]:
        url = f"{config['host']}/predicate/v1/{name}"
        try:
            status, body = get(url)
        except ReadFailed as error:
            failed.append(str(error))
            continue
        if status != 200 or name.encode() not in body:
            missing.append(f"{name} ({status})")
    if failed:
        return Check(1, "identifier", INCONCLUSIVE, "; ".join(failed))
    if missing:
        return Check(1, "identifier", RED, "no page for " + ", ".join(missing))
    return Check(1, "identifier", GREEN, f"{len(field['predicates'])} predicate pages answer 200")


def latest_release(config: dict[str, Any], get: Fetch) -> tuple[str, str | None]:
    """The latest release's tag and the download URL of its CORPUS-DIGESTS.txt."""
    release = fetch_json(get, f"{API}/repos/{config['repository']}/releases/latest")
    assets = {asset["name"]: asset["browser_download_url"] for asset in release.get("assets", [])}
    return release["tag_name"], assets.get("CORPUS-DIGESTS.txt")


def check_corpus_released(
    config: dict[str, Any], field: dict[str, Any], get: Fetch
) -> tuple[Check, str | None]:
    try:
        tag, digests_url = latest_release(config, get)
        if digests_url is None:
            return Check(2, "corpus-released", RED, f"{tag} carries no CORPUS-DIGESTS.txt"), tag
        status, body = get(digests_url)
    except ReadFailed as error:
        return Check(2, "corpus-released", INCONCLUSIVE, str(error)), None
    if status != 200:
        return Check(
            2, "corpus-released", INCONCLUSIVE, f"CORPUS-DIGESTS.txt answered {status}"
        ), None
    lines = [
        line for line in body.decode("utf-8").splitlines() if line and not line.startswith("#")
    ]
    if not lines:
        return Check(
            2, "corpus-released", INCONCLUSIVE, f"{tag} CORPUS-DIGESTS.txt lists no corpus at all"
        ), None
    wanted = f"{field['corpus']}/MANIFEST.json"
    for line in lines:
        parts = line.split()
        if len(parts) >= 2 and parts[1] == wanted:
            return Check(
                2, "corpus-released", GREEN, f"{tag} lists {field['corpus']} at {parts[0][:12]}"
            ), tag
    return Check(
        2, "corpus-released", RED, f"{tag} lists {len(lines)} corpora, not {field['corpus']}"
    ), tag


def extract_tag(tag: str, paths: list[str], dest: Path) -> None:
    """Write the named paths of `tag` under dest, fetching the tag if it is absent."""
    have = subprocess.run(
        ["git", "-C", str(ROOT), "rev-parse", "-q", "--verify", f"refs/tags/{tag}"],
        capture_output=True,
    )
    if have.returncode != 0:
        got = subprocess.run(
            ["git", "-C", str(ROOT), "fetch", "-q", "--depth=1", "origin", "tag", tag],
            capture_output=True,
            text=True,
        )
        if got.returncode != 0:
            raise ReadFailed(f"git fetch tag {tag}: {got.stderr.strip()}")
    archive = dest / "tag.tar"
    made = subprocess.run(
        ["git", "-C", str(ROOT), "archive", "-o", str(archive), tag, *paths],
        capture_output=True,
        text=True,
    )
    if made.returncode != 0:
        raise ReadFailed(f"git archive {tag}: {made.stderr.strip()}")
    with tarfile.open(archive) as handle:
        handle.extractall(dest, filter="data")


def run_tally(tree: Path, corpus: str) -> dict[str, Any]:
    """Run the reference stage's tally under the tag's pinned reference verifier."""
    script = tree / "tally.py"
    script.write_text(TALLY, encoding="utf-8")
    done = subprocess.run(
        [
            "uv",
            "run",
            "--no-project",
            "-q",
            "-p",
            "3.13",
            "--with-requirements",
            str(tree / "action-reference-requirements.txt"),
            "python",
            "-I",
            str(script),
            str(tree),
            corpus,
        ],
        capture_output=True,
        text=True,
        timeout=900,
    )
    if done.returncode != 0:
        raise ReadFailed(f"reference tally exited {done.returncode}: {done.stderr.strip()[-400:]}")
    return json.loads(done.stdout.strip().splitlines()[-1])


def check_verifier_released(
    field: dict[str, Any],
    tag: str | None,
    corpus_check: Check,
    tally: Callable[[str, str], dict[str, Any]],
) -> Check:
    if corpus_check.status == INCONCLUSIVE or tag is None:
        return Check(3, "verifier-released", INCONCLUSIVE, "the release could not be read")
    if corpus_check.status == RED:
        return Check(
            3, "verifier-released", RED, f"{tag} ships no {field['corpus']} for a verifier to judge"
        )
    try:
        result = tally(tag, field["corpus"])
    except (ReadFailed, subprocess.TimeoutExpired, ValueError) as error:
        return Check(3, "verifier-released", INCONCLUSIVE, str(error))
    checked, total = result["checked"], result["total"]
    status = GREEN if total > 0 and checked == total else RED
    return Check(
        3, "verifier-released", status, f"{tag} reference verifier checked {checked} of {total}"
    )


def tag_tally(tag: str, corpus: str) -> dict[str, Any]:
    with tempfile.TemporaryDirectory() as tmp:
        tree = Path(tmp)
        extract_tag(tag, [corpus, *TAG_PATHS], tree)
        return run_tally(tree, corpus)


def outside_run(
    config: dict[str, Any], field: dict[str, Any], entry: dict[str, str], get: Fetch
) -> tuple[bool, str]:
    """Whether one recorded outside workflow runs the corpus and last passed."""
    repo, workflow = entry["repo"], entry["workflow"]
    if repo.split("/")[0].lower() in {owner.lower() for owner in config["excluded_owners"]}:
        return False, f"{repo} is owned by this organisation"
    meta = fetch_json(get, f"{API}/repos/{repo}")
    branch = meta["default_branch"]
    content = fetch_json(get, f"{API}/repos/{repo}/contents/{workflow}?ref={branch}")
    text = base64.b64decode(content["content"]).decode("utf-8")
    if config["repository"] not in text and "agent-evidence-vectors" not in text:
        return False, f"{repo}:{workflow} does not use this repository's Action or package"
    if field["corpus"] not in text:
        return False, f"{repo}:{workflow} does not name {field['corpus']}"
    name = workflow.rsplit("/", 1)[-1]
    runs = fetch_json(
        get,
        f"{API}/repos/{repo}/actions/workflows/{name}/runs?branch={branch}&status=completed&per_page=1",
    )
    if not runs.get("workflow_runs"):
        return False, f"{repo}:{workflow} has no completed run on {branch}"
    run = runs["workflow_runs"][0]
    if run["conclusion"] != "success":
        return False, f"{repo}:{workflow} last run {run['conclusion']} ({run['html_url']})"
    return True, f"{repo}:{workflow} passed ({run['html_url']})"


def check_outside_ci(config: dict[str, Any], field: dict[str, Any], get: Fetch) -> Check:
    entries = field.get("outside_ci", [])
    if not entries:
        return Check(
            4, "outside-ci", RED, "no outside workflow is recorded in release/field-readiness.toml"
        )
    passing, notes = [], []
    for entry in entries:
        try:
            ok, note = outside_run(config, field, entry, get)
        except (ReadFailed, KeyError, ValueError) as error:
            return Check(4, "outside-ci", INCONCLUSIVE, f"{entry.get('repo')}: {error}")
        (passing if ok else notes).append(note)
    if passing:
        return Check(4, "outside-ci", GREEN, "; ".join(passing))
    return Check(4, "outside-ci", RED, "; ".join(notes))


def check_adopter_record(field_name: str, records: Path | None) -> Check:
    if records is None:
        return Check(
            5, "adopter-record", NOT_READ, "adopter records are not held in this repository"
        )
    try:
        held = json.loads(records.read_text(encoding="utf-8")).get("records", [])
    except (OSError, ValueError) as error:
        return Check(5, "adopter-record", INCONCLUSIVE, f"{records}: {error}")
    named = [
        row
        for row in held
        if row.get("field") == field_name
        and re.fullmatch(r"sha256:[0-9a-f]{64}", str(row.get("digest", "")))
    ]
    if named:
        return Check(
            5,
            "adopter-record",
            GREEN,
            f"{len(named)} record(s), first dated {named[0].get('date')}",
        )
    return Check(5, "adopter-record", RED, f"{records} holds no record for {field_name}")


def run_checks(
    field_name: str,
    config: dict[str, Any],
    get: Fetch = fetch,
    tally: Callable[[str, str], dict[str, Any]] = tag_tally,
    records: Path | None = None,
) -> list[Check]:
    field = config["fields"][field_name]
    corpus_check, tag = check_corpus_released(config, field, get)
    return [
        check_identifier(config, field, get),
        corpus_check,
        check_verifier_released(field, tag, corpus_check, tally),
        check_outside_ci(config, field, get),
        check_adopter_record(field_name, records),
    ]


def summary(field_name: str, checks: list[Check]) -> str:
    counts = {
        state: sum(1 for c in checks if c.status == state)
        for state in (GREEN, RED, INCONCLUSIVE, NOT_READ)
    }
    return (
        f"field {field_name}: {counts[GREEN]} of {len(checks)} green "
        f"({counts[RED]} red, {counts[INCONCLUSIVE]} inconclusive, {counts[NOT_READ]} not read)"
    )


def exit_code(checks: list[Check], require_green: int | None) -> int:
    if any(c.status == INCONCLUSIVE for c in checks):
        return 2
    if require_green is not None and sum(c.status == GREEN for c in checks) < require_green:
        return 1
    return 0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").split("\n\n")[0])
    parser.add_argument("field")
    parser.add_argument("--config", type=Path, default=CONFIG)
    parser.add_argument(
        "--records",
        type=Path,
        help="JSON file of adopter records, {records: [{field, date, digest}]}",
    )
    parser.add_argument("--require-green", type=int)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    config = tomllib.loads(args.config.read_text(encoding="utf-8"))
    if args.field not in config["fields"]:
        parser.error(f"{args.field} is not a field in {args.config}")
    checks = run_checks(args.field, config, records=args.records)
    line = summary(args.field, checks)
    if args.json:
        print(
            json.dumps(
                {"field": args.field, "summary": line, "checks": [asdict(c) for c in checks]},
                indent=2,
            )
        )
    else:
        for c in checks:
            print(f"check {c.number} {c.name:<18} {c.status:<12} {c.detail}")
        print(line)
    step_summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if step_summary:
        rows = [f"## {line}\n\n| check | status | detail |\n| --- | --- | --- |\n"]
        rows += [f"| {c.number} {c.name} | {c.status} | {c.detail} |\n" for c in checks]
        with open(step_summary, "a", encoding="utf-8") as handle:
            handle.write("".join(rows))
    return exit_code(checks, args.require_green)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
