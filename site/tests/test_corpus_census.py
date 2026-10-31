"""tools/corpus_census.py counts each rule from the repository's own fields at a commit."""

from __future__ import annotations

import json
import subprocess
import tomllib
from collections import Counter
from pathlib import Path

import pytest

import corpus_census
import gen_atlas

ROOT = Path(__file__).resolve().parent.parent


def git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True,
                          check=True).stdout.strip()


@pytest.fixture()
def clone(tmp_path: Path) -> tuple[Path, str]:
    repo = tmp_path / "vectors"
    repo.mkdir()
    git(repo, "init", "-q")
    files = {
        "k/MANIFEST.json": {"vectors": [{"kind": "accept"}, {"kind": "reject"}, {"kind": "reject"},
                                        {"kind": "indeterminate"}]},
        "d/MANIFEST.json": {"vectors": [{"expected": {"decision": "not_established"}},
                                        {"expected": {"decision": "supported"}}]},
        "c/MANIFEST.json": {"vectors": [{}, {}, {}], "counts": {"accept": 2, "reject": 1, "total": 3}},
        "bad/MANIFEST.json": {"vectors": [{}, {}], "counts": {"verified": 1}},
        "r/cases/a/expected.json": {"role": "case"},
        "r/cases/b/expected.json": {"role": "control"},
        "r/cases/c/expected.json": {"role": "control"},
    }
    for rel, body in files.items():
        (repo / rel).parent.mkdir(parents=True, exist_ok=True)
        (repo / rel).write_text(json.dumps(body), encoding="utf-8")
    git(repo, "add", ".")
    git(repo, "-c", "user.name=t", "-c", "user.email=t@example.invalid", "commit", "-q", "-m", "c")
    return repo, git(repo, "rev-parse", "HEAD")


@pytest.mark.parametrize(("directory", "rule", "expected"), [
    ("k", "kind", (4, "1 accept, 2 reject, 1 indeterminate")),
    ("d", "decision", (2, "1 supported, 1 not established")),
    ("c", "counts", (3, "2 accept, 1 reject")),
    ("r", "case-role", (3, "1 case, 2 controls")),
])
def test_each_rule_counts_its_own_field(clone: tuple[Path, str], directory: str, rule: str,
                                        expected: tuple[int, str]) -> None:
    repo, commit = clone
    assert corpus_census.census({"dir": directory, "commit": commit, "count": rule}, repo) == expected


def test_counts_that_do_not_sum_to_the_members_are_refused(clone: tuple[Path, str]) -> None:
    repo, commit = clone
    with pytest.raises(ValueError, match="do not sum"):
        corpus_census.census({"dir": "bad", "commit": commit, "count": "counts"}, repo)


def test_an_unknown_rule_is_refused(clone: tuple[Path, str]) -> None:
    repo, commit = clone
    with pytest.raises(ValueError, match="unknown count rule"):
        corpus_census.census({"dir": "k", "commit": commit, "count": "guess"}, repo)


def test_split_order_is_fixed() -> None:
    assert corpus_census.split_text(Counter({"gap": 2, "reject": 8, "accept": 12})) == "12 accept, 8 reject, 2 gap"


def test_every_atlas_corpus_is_pinned_and_linked_at_its_commit() -> None:
    data = tomllib.loads((ROOT / "data" / "atlas.toml").read_text(encoding="utf-8"))
    rules = {"kind", "decision", "counts", "case-role", "conformance", "observer-outcome"}
    for c in data["corpus"]:
        assert len(c["commit"]) == 40 and c["count"] in rules and c["pin"], c["dir"]
        assert f"/tree/{c['commit']}/" in gen_atlas.corpus_link(c)
    release = [c for c in data["corpus"] if c["pin"] == data["meta"]["corpus_release"]]
    assert {c["commit"] for c in release} == {data["meta"]["corpus_commit"]}
