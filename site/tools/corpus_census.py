#!/usr/bin/env python3
"""Re-count every atlas corpus from its own manifest at its pinned commit.

    python3 tools/corpus_census.py --clone OWNER/REPO=PATH [--clone ...]

Each `[[corpus]]` entry in data/atlas.toml names a repository, a commit and a
`count` rule. This tool reads the entry's manifest (or, for the case-role rule,
its case files) with `git show <commit>:<path>` from a local clone, recounts the
members and the split the rule names, prints both beside the recorded values, and
exits 1 if any entry differs or could not be read. Every clone must contain the
pinned commit; nothing is fetched.

The rules are the repositories' own fields, never a hand count:

  kind              each manifest entry's `kind` (accept, reject, indeterminate, gap)
  decision          each entry's `expected.decision`
  counts            the manifest's own `counts` object, less any `total` member, which
                    must sum to the number of members
  case-role         the `role` of every `cases/*/expected.json`
  conformance       each member's `expected.conformance`
  observer-outcome  each vector's `expected.overall`, or `refused` when it has none
"""

from __future__ import annotations

import json
import subprocess
import sys
import tomllib
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data" / "atlas.toml"
DEFAULT_REPO = "probityai/agent-evidence-vectors"

# Order in which split buckets are printed; any other bucket follows, sorted.
ORDER = ["accept", "reject", "indeterminate", "gap", "valid", "invalid", "supported",
         "verified", "accepted", "established", "contradicted", "failed", "rejected",
         "not established", "no verdict", "refused", "case", "control"]
LABEL = {"notEstablished": "not established"}
PLURAL = {"case": "cases", "control": "controls"}


def git_show(clone: Path, commit: str, rel: str) -> str:
    return subprocess.run(["git", "-C", str(clone), "show", f"{commit}:{rel}"],
                          capture_output=True, text=True, check=True).stdout


def git_ls(clone: Path, commit: str, rel: str) -> list[str]:
    out = subprocess.run(["git", "-C", str(clone), "ls-tree", "-r", "--name-only", commit, rel],
                         capture_output=True, text=True, check=True).stdout
    return out.split()


def bucket(value: object) -> str:
    text = str(value)
    return LABEL.get(text, text.replace("_", " ").lower())


def split_text(counts: Counter[str], plural: bool = False) -> str:
    keys = sorted(counts, key=lambda k: (ORDER.index(k) if k in ORDER else len(ORDER), k))
    parts = []
    for k in keys:
        word = PLURAL.get(k, k) if plural and counts[k] != 1 else k
        parts.append(f"{counts[k]} {word}")
    return ", ".join(parts)


def census(entry: dict, clone: Path) -> tuple[int, str]:
    """Return (members, split) for one corpus entry, read from its clone."""
    commit, path, rule = entry["commit"], entry.get("path", entry["dir"]), entry["count"]
    if rule == "case-role":
        files = [f for f in git_ls(clone, commit, f"{path}/cases") if f.endswith("/expected.json")]
        roles = Counter(bucket(json.loads(git_show(clone, commit, f))["role"]) for f in files)
        return len(files), split_text(roles, plural=True)
    manifest = json.loads(git_show(clone, commit, entry.get("manifest", f"{path}/MANIFEST.json")))
    members = manifest.get("vectors", manifest.get("members"))
    if not isinstance(members, list):
        raise ValueError("the manifest carries no member list")
    if rule == "kind":
        counts = Counter(bucket(m["kind"]) for m in members)
    elif rule == "decision":
        counts = Counter(bucket(m["expected"]["decision"]) for m in members)
    elif rule == "counts":
        counts = Counter({bucket(k): v for k, v in manifest["counts"].items() if k != "total"})
        if sum(counts.values()) != len(members):
            raise ValueError(f"counts {dict(counts)} do not sum to {len(members)} members")
    elif rule == "conformance":
        counts = Counter(bucket(m["expected"]["conformance"]) for m in members)
    elif rule == "observer-outcome":
        counts = Counter(bucket(m["expected"].get("overall", "refused")) for m in members)
    else:
        raise ValueError(f"unknown count rule {rule!r}")
    return len(members), split_text(counts)


def parse_clones(argv: list[str]) -> dict[str, Path]:
    clones: dict[str, Path] = {}
    for i, arg in enumerate(argv):
        if arg == "--clone" and i + 1 < len(argv):
            repo, _, path = argv[i + 1].partition("=")
            clones[repo] = Path(path)
    return clones


def main(argv: list[str]) -> int:
    clones = parse_clones(argv)
    if not clones:
        print(__doc__)
        return 2
    corpora = tomllib.loads(DATA.read_text(encoding="utf-8"))["corpus"]
    bad = 0
    for entry in corpora:
        repo = entry.get("repo", DEFAULT_REPO)
        if repo not in clones:
            print(f"UNREAD   {entry['dir']:40} no clone given for {repo}")
            bad += 1
            continue
        try:
            members, split = census(entry, clones[repo])
        except (subprocess.CalledProcessError, ValueError, KeyError, json.JSONDecodeError) as e:
            print(f"UNREAD   {entry['dir']:40} {type(e).__name__}: {e}")
            bad += 1
            continue
        same = members == entry["members"] and split == entry["split"]
        bad += 0 if same else 1
        tag = "same   " if same else "CHANGED"
        print(f"{tag}  {entry['dir']:40} {members:>4}  {split}"
              + ("" if same else f"   (recorded {entry['members']}: {entry['split']})"))
    print(f"{len(corpora) - bad} of {len(corpora)} corpora match data/atlas.toml")
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
