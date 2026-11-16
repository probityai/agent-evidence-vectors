#!/usr/bin/env python3
"""Tests for scripts/archived-repo-gate.py.

Each case writes one line into a scratch git repository and asserts whether the gate
refuses it, so the gate is seen to go red on a live reference to any archived
repository and to stay green on an identifier or on a record that exists only in the
archive. The live check is run against a fake GitHub.

Usage: python3 scripts/archived-repo-gate-test.py
Exit 0 when every case holds; 1 naming each case that does not.
"""

from __future__ import annotations

import importlib.util
import subprocess
import sys
import tempfile
import urllib.error
from pathlib import Path

HERE = Path(__file__).resolve().parent
_SPEC = importlib.util.spec_from_file_location("archived_repo_gate", HERE / "archived-repo-gate.py")
if _SPEC is None or _SPEC.loader is None:
    raise ImportError("cannot load scripts/archived-repo-gate.py")
gate = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(gate)

REPOS = gate.load_repos((HERE / "archived-repos.toml").read_text(encoding="utf-8"))
OLD = "https://github.com/probityai/agent-evidence"
VOCAB = "https://github.com/probityai/agent-evidence-vocabulary"
PREDICATE = f"{VOCAB}/blob/main/docs/predicates/agent-change-admission-v1.md"
SHA = "0123456789abcdef0123456789abcdef01234567"

CASES = [
    # (description, file, line, refused)
    ("a blob link", "README.md", f"[guide]({OLD}/blob/main/README.md)", True),
    ("the bare repository URL", "README.md", f"See {OLD} for more.", True),
    ("an Action ref", "ci.yml", "- uses: probityai/agent-evidence@action-v0.1.0", True),
    ("a clone line", "README.md", f"git clone {OLD}", True),
    ("a transferred issue", "README.md", f"[thread]({OLD}/issues/24)", True),
    ("a transferred issue in short form", "README.md", "see probityai/agent-evidence#24", True),
    ("an issue number that only starts like an untransferred one", "README.md", f"{OLD}/issues/300", True),
    ("a CI run", "README.md", f"[run]({OLD}/actions/runs/40802484844)", False),
    ("a pull request", "README.md", f"[PR]({OLD}/pull/53)", False),
    ("an untransferred issue", "README.md", f"[run]({OLD}/issues/35)", False),
    ("an untransferred issue in short form", "vocab.yaml", "read on probityai/agent-evidence#32 at", False),
    (
        "a site workflow, imported here with the Atlas tree",
        "gen.py",
        f"{OLD}/blob/main/.github/workflows/site-board.yml",
        True,
    ),
    ("the vectors repository", "README.md", "https://github.com/probityai/agent-evidence-vectors", False),
    ("an allowlisted file", "CHANGELOG.md", f"now points at {OLD}, where", False),
    ("a live link beside a CI run", "README.md", f"{OLD}/actions/runs/1 and {OLD}/blob/main/x", True),
    # The vocabulary and admission repositories, which the first version of the gate did not know.
    ("the vocabulary repository", "README.md", f"[vocabulary]({VOCAB})", True),
    ("a vocabulary file", "README.md", f"[x]({VOCAB}/blob/main/vocabulary.yaml)", True),
    ("the admission repository", "README.md", "https://github.com/probityai/agent-evidence-admission", True),
    ("a pull request of the vocabulary repository", "README.md", f"[PR]({VOCAB}/pull/2)", False),
    ("a vocabulary issue", "README.md", f"[thread]({VOCAB}/issues/4)", True),
    ("a file at a full commit id", "README.md", f"{VOCAB}/blob/{SHA}/README.md", False),
    ("a file at a short commit id", "README.md", f"{VOCAB}/blob/0123456/README.md", True),
    (
        "a raw file at a full commit id",
        "m.json",
        f"https://raw.githubusercontent.com/probityai/agent-evidence-atlas/{SHA}/a.zip",
        False,
    ),
    ("a raw file on a branch", "m.json", "https://raw.githubusercontent.com/probityai/jcs-admit/main/a.zip", True),
    ("the archive organisation", "README.md", "https://github.com/probityai-archive/agent-evidence-vocabulary", False),
    ("an old handle", "README.md", "https://github.com/astrogilda/agent-evidence-vocabulary", True),
    ("a clone by ssh", "README.md", "git clone git@github.com:probityai/ratchet.git", True),
    # Identifiers: a predicate type URI, an npm scope and an MCP registry namespace.
    ("a predicate type URI as an identifier", "case.json", f'"predicateType": "{PREDICATE}",', False),
    ("a predicate type URI inside backticks", "doc.md", f"`{PREDICATE}`", False),
    ("a predicate type URI as a link target", "README.md", f"[the predicate]({PREDICATE})", True),
    ("a predicate type URI beside a repository link", "README.md", f"{PREDICATE} and {VOCAB}", True),
    ("another path in the vocabulary repository", "README.md", f"{VOCAB}/blob/main/docs/other.md", True),
    ("an npm scope", "package.json", '"name": "@probityai/dsse",', False),
    ("an npm scope with a subpath", "x.mjs", 'import("@probityai/dsse/browser")', False),
    ("an MCP registry namespace", "server.json", '"io.github.probityai/agent-evidence-admission": {', False),
    ("a container image path", "RELEASING.md", "ghcr.io/probityai/agent-evidence-mcp:1.2.3", False),
    ("a container image path beside a repository link", "RELEASING.md", f"ghcr.io/probityai/dsse and {VOCAB}", True),
    ("a Go module path", "go.mod", "module github.com/probityai/dsse/vectors/generate", True),
] + [
    (f"a link to {repo.name}", "README.md", f"[x](https://github.com/probityai/{repo.name}/tree/main)", True)
    for repo in REPOS
]


def run_case(line: str, name: str) -> list[str]:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        subprocess.run(["git", "init", "-q", str(root)], check=True)
        (root / name).write_text(line + "\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(root), "add", name], check=True)
        return list(gate.findings(root, {"CHANGELOG.md"}, REPOS))


def fake_github(
    *, extra: tuple[str, ...] = (), redirected: str = "", missing_home: str = "", unarchived: str = ""
):
    """A fetch that answers as GitHub would, with one thing wrong when asked."""
    archive = [{"name": r.name} for r in REPOS] + [{"name": n} for n in extra]

    def fetch(url: str) -> object:
        if "/orgs/probityai-archive/repos" in url:
            return archive if "page=1" in url else []
        for repo in REPOS:
            if url == f"{gate.API}/repos/probityai/{repo.name}":
                if redirected == repo.name:
                    return {"full_name": f"probityai/{repo.name}", "archived": False}
                return {"full_name": f"probityai-archive/{repo.name}", "archived": unarchived != repo.name}
            owner, repository, *path = repo.home.split("/", 2)
            if url == f"{gate.API}/repos/{owner}/{repository}" + (f"/contents/{path[0]}" if path else ""):
                if missing_home == repo.name:
                    raise urllib.error.HTTPError(url, 404, "Not Found", {}, None)  # type: ignore[arg-type]
                return {}
        raise AssertionError(f"unexpected request {url}")

    return fetch


def live_cases() -> list[str]:
    failures = []
    if problems := gate.live_problems(REPOS, fake_github()):
        failures.append(f"a true list was refused: {problems}")
    for label, kwargs, needle in [
        ("a repository with no row", {"extra": ("brand-new",)}, "brand-new"),
        ("a redirect that ended", {"redirected": "dsse"}, "resolves to"),
        ("a home that is gone", {"missing_home": "ratchet"}, "HTTP 404"),
        ("a repository that is not archived", {"unarchived": "jcs-admit"}, "is not archived"),
    ]:
        problems = gate.live_problems(REPOS, fake_github(**kwargs))
        if not any(needle in p for p in problems):
            failures.append(f"{label} was not refused: {problems}")
    return failures


def list_cases() -> list[str]:
    failures = []
    for label, text in [
        ("a row with no home", '[[repo]]\nname = "x"\n'),
        ("an empty list", ""),
    ]:
        try:
            gate.load_repos(text)
            failures.append(f"{label} was accepted")
        except ValueError:
            pass
    names = [r.name for r in REPOS]
    if len(names) != len(set(names)):
        failures.append("the list names a repository twice")
    return failures


def main() -> int:
    failures = []
    for description, name, line, refused in CASES:
        hits = run_case(line, name)
        if bool(hits) != refused:
            failures.append(f"{description}: expected {'a refusal' if refused else 'a pass'}, got {hits}")
    try:
        gate.allowed_paths("some/file.md\n")
        failures.append("an allowlist line with no reason was accepted")
    except ValueError:
        pass
    if not gate.is_allowed("pages/vocab/v1/x/index.html", {"pages/vocab/**"}):
        failures.append("a dir/** pattern did not match a file under it")
    failures += live_cases() + list_cases()
    for failure in failures:
        print(failure, file=sys.stderr)
    if failures:
        return 1
    print(f"archived-repo-gate: {len(CASES) + 2 + 5 + 3} cases hold")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
