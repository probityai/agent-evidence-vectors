#!/usr/bin/env python3
"""Re-derive every automatable claim in CLAIMS.md and compare it with the recorded value.

    python3 tools/rederive.py              print recorded vs current for every row
    python3 tools/rederive.py --strict     exit 1 if any value changed or could not be read
    python3 tools/rederive.py --unread-fails
                                           exit 1 only if a row could not be read; a moved
                                           value is reported, not failed (the weekly CI mode)

Only the rows whose claim id appears in this repository's CLAIMS.md are read, so a
ledger that covers fewer pages re-derives fewer rows; the count printed at the end
says how many. No credentials are needed. GitHub's unauthenticated API allows 60 requests an hour,
which covers one run; set GITHUB_TOKEN to raise that limit. A read that fails is
printed as UNREAD with its reason and is never reported as unchanged.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parent.parent
UA = "agent-evidence-atlas-claim-check (https://github.com/probityai/agent-evidence-atlas)"


def get_json(url: str) -> dict:
    headers = {"User-Agent": UA, "Accept": "application/json"}
    token = os.environ.get("GITHUB_TOKEN")
    if token and urlparse(url).hostname == "api.github.com":
        headers["Authorization"] = f"Bearer {token}"
    with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=30) as r:
        return json.load(r)


def stars(repo: str) -> str:
    return str(get_json(f"https://api.github.com/repos/{repo}")["stargazers_count"])


def pr_state(repo: str, number: int) -> str:
    d = get_json(f"https://api.github.com/repos/{repo}/pulls/{number}")
    return "merged" if d.get("merged_at") else d["state"]


def issue_state(repo: str, number: int) -> str:
    return get_json(f"https://api.github.com/repos/{repo}/issues/{number}")["state"]


def crate_version(name: str) -> str:
    return get_json(f"https://crates.io/api/v1/crates/{name}")["crate"]["max_version"]


def pypi_version(name: str) -> str:
    return get_json(f"https://pypi.org/pypi/{name}/json")["info"]["version"]


def zenodo_version(record: int) -> str:
    d = get_json(f"https://zenodo.org/api/records/{record}")
    return f"{d['metadata'].get('version')} {d['metadata'].get('publication_date')}"


def latest_tag(repo: str) -> str:
    tags = get_json(f"https://api.github.com/repos/{repo}/tags?per_page=1")
    return tags[0]["name"] if tags else "no tags"


def vector_total() -> str:
    """Count the members of every atlas corpus pinned at the counted vectors release.

    Reads data/atlas.toml for the corpora whose `pin` is `meta.corpus_release`, then
    each one's manifest at its pinned commit; a case-role corpus has no manifest and
    is counted by the case directories it holds. tools/corpus_census.py recounts the
    splits as well, from local clones.
    """
    import tomllib
    data = tomllib.loads((ROOT / "data" / "atlas.toml").read_text(encoding="utf-8"))
    release = data["meta"]["corpus_release"]
    corpora = [c for c in data["corpus"] if c["pin"] == release]
    total = 0
    for c in corpora:
        repo = c.get("repo", "probityai/agent-evidence-vectors")
        path = c.get("path", c["dir"])
        if c["count"] == "case-role":
            listing = get_json(f"https://api.github.com/repos/{repo}/contents/{path}/cases?ref={c['commit']}")
            total += sum(1 for item in listing if item["type"] == "dir")
            continue
        manifest = c.get("manifest", f"{path}/MANIFEST.json")
        m = get_json(f"https://raw.githubusercontent.com/{repo}/{c['commit']}/{manifest}")
        total += len(m.get("vectors", m.get("members", [])))
    return f"{total} in {len(corpora)}"


def file_sha256(rel: str) -> str:
    return hashlib.sha256((ROOT / rel).read_bytes()).hexdigest()


def line_count(rel: str) -> str:
    return str(len((ROOT / rel).read_text(encoding="utf-8").splitlines()))


def demo_run() -> str:
    proc = subprocess.run(["./run-demo.sh"], cwd=ROOT / "demo" / "verifier",
                          capture_output=True, text=True, check=False)
    return f"exit {proc.returncode}"


# (claim id, recorded value, reader)
def atlas_star_rows() -> list:
    """One row per atlas entry that names a repository, read from data/atlas.toml."""
    import tomllib
    data = tomllib.loads((ROOT / "data" / "atlas.toml").read_text(encoding="utf-8"))
    rows = []
    for e in data["entry"]:
        if "repo" in e:
            repo = e["repo"]
            rows.append((f"A-stars {repo}", str(e["stars"]), lambda r=repo: stars(r)))
    return rows


VERSION_READERS = {"tag": latest_tag, "pypi": pypi_version, "crate": crate_version}
PULL = re.compile(r"^https://github\.com/([^/]+/[^/]+)/pull/([0-9]+)$")


def artifact_release_rows() -> list:
    """One row per artifact release, with the recorded value taken from data/atlas.toml.

    The page shows each artifact's `release`, which must contain its `version`
    (tools/gen_atlas.py refuses otherwise), so the page and this check read one value.
    """
    import tomllib
    data = tomllib.loads((ROOT / "data" / "atlas.toml").read_text(encoding="utf-8"))
    rows = []
    for a in data["artifact"]:
        kind, _, target = a["version_from"].partition(":")
        reader = VERSION_READERS[kind]
        rows.append((f"A-38 {a['name']}", a["version"], lambda r=reader, x=target: r(x)))
    return rows


def contribution_state_rows() -> list:
    """One row per contribution that is a GitHub pull request, recorded as its label."""
    import tomllib
    data = tomllib.loads((ROOT / "data" / "atlas.toml").read_text(encoding="utf-8"))
    rows = []
    for c in data["contribution"]:
        m = PULL.match(c["url"])
        if m:
            rows.append((f"A-39 {c['where']}", c["label"],
                         lambda r=m.group(1), n=int(m.group(2)): pr_state(r, n)))
    return rows


ROWS = atlas_star_rows() + artifact_release_rows() + contribution_state_rows() + [
    ("A-38c", "1197 in 24", vector_total),
    ("I-01", "v6 2026-08-14", lambda: zenodo_version(21935891)),
    ("D-02", "cc938c6038536dcb0d63269dd96cd64bed2d8d575fe212b72593c7f2ca92399b",
     lambda: file_sha256("demo/verifier/inputs/vcc938c6038536dcb.json")),
    ("D-03", "169", lambda: line_count("demo/verifier/src/main.rs")),
]


def ledger_ids() -> set[str]:
    """Claim ids that have a row in CLAIMS.md, such as A-38, D-02 or A-stars."""
    text = (ROOT / "CLAIMS.md").read_text(encoding="utf-8")
    return set(re.findall(r"^\| ([A-Z]-[0-9A-Za-z]+) \|", text, flags=re.MULTILINE))


def in_ledger(cid: str, ids: set[str]) -> bool:
    """A-39c belongs to row A-39; A-stars <repo> belongs to row A-stars."""
    base = cid.split()[0]
    return base in ids or re.sub(r"[a-z]$", "", base) in ids


def main() -> int:
    strict = "--strict" in sys.argv[1:]
    run_demo = "--demo" in sys.argv[1:]
    ids = ledger_ids()
    if not ids:
        print("CLAIMS.md carries no claim rows; nothing was re-derived (not a pass)")
        return 2
    rows = [r for r in ROWS if in_ledger(r[0], ids)]
    rows += [("D-04", "exit 0", demo_run)] if (run_demo and "D-04" in ids) else []
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    print(f"re-derived at {now}")
    bad = 0
    unread = 0
    for cid, recorded, reader in rows:
        try:
            current = reader()
        except Exception as e:  # noqa: BLE001 - every failure is printed, none is hidden
            print(f"UNREAD   {cid:44} recorded {recorded!r}: {type(e).__name__}: {e}")
            bad += 1
            unread += 1
            continue
        tag = "same   " if current == recorded else "CHANGED"
        if current != recorded:
            bad += 1
        print(f"{tag}  {cid:44} recorded {recorded!r} current {current!r}")
    print(f"{len(rows) - bad} of {len(rows)} unchanged; {unread} could not be read")
    if "--unread-fails" in sys.argv[1:]:
        return 1 if unread else 0
    return 1 if (strict and bad) else 0


if __name__ == "__main__":
    raise SystemExit(main())
