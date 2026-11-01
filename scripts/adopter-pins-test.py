#!/usr/bin/env python3
"""Every name and path an outside adopter's CI pins still resolves.

A tag is immutable, so a pin at a tag never breaks when this tree changes. What
breaks is the next release an adopter takes, and every pin of ours ships with a
version-bump bot entry, so each release is taken. This check holds the tree to
the names and paths those pinned jobs read, measured from their own files:

  P1  action.yml at the root, with every input and output name an adopter's
      `with:` block or a later step may read
  P2  the corpus ids adopters pass to --corpus or the Action, each a corpus the
      wheel ships
  P3  the flagship corpus at vectors/ in the tree: an adopter checks out a commit
      and runs a checker over <clone>/vectors
  P4  release/cosign.pub at its path, with the digest an adopter pins it by
  P5  the release digest list's line format, which an adopter parses:
      <digest> <id>/MANIFEST.json <suite> vectors=<n> ...
  P6  the release asset names an adopter downloads from releases/download/<tag>/
  P7  the Go module path, the `go install` path cmd/aee-verify, and the Go
      packages aee and observedeffect
  P8  the distribution name, the console script and its flags
  P9  CITATION.cff and .zenodo.json at the root, where GitHub and Zenodo read them
  P10 each published npm package's repository.directory names the directory the
      package lives in

With --wheel PATH it also checks the built wheel:

  W1  agent_evidence_vectors/corpora/<id>/MANIFEST.json for every pinned id,
      the path an adopter joins by hand after `pip install`
  W2  agent_evidence_vectors/corpora/corpora/jcs-byte-vectors/cases.json and its
      README, which an SDK's CI reads from the installed package
  W3  the console script entry point

Exit 0 when every pin resolves, 1 naming each that does not.
"""

from __future__ import annotations

import argparse
import configparser
import hashlib
import json
import re
import subprocess
import sys
import tomllib
import zipfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

#: Corpus ids passed by outside CI, with who passes them.
PINNED_CORPORA = {
    "vectors": "the default corpus; aee-checker runs <clone>/vectors",
    "vectors-receipt-signature": "ScopeBlind agent-governance-testvectors run.sh",
    "vectors-observed-effect": "agentrust-io integrations README",
    "vectors-uncertain-effect": "this repository's README Action example",
    "vectors-agent-audit-record": "Laurent-Lemonnier run.sh joins its wheel path",
    "vectors-anchored-chain": "AbdaullahAG CI requirements pin",
}
ACTION_INPUTS = [
    "verifier", "runtime", "corpus", "vectors", "tag", "artifact-name", "report-path", "retention-days",
    "check", "document", "artifacts", "required", "statement", "rules", "pins",
]
ACTION_OUTPUTS = [
    "report", "vectors", "conform", "executed", "result", "refusals", "reference-checked",
    "reference-total", "full-release", "reference-verifier-id",
]
COSIGN_SHA256 = "15fccb1635dd1d9333146cb389f26fa3c3b9213aeed1da945ea1f51a2dc1be84"
RELEASE_ASSETS = ["CORPUS-DIGESTS.txt", "CORPUS-DIGESTS.txt.sig"]
GO_MODULE = "github.com/probityai/agent-evidence-vectors"
GO_PACKAGES = ["cmd/aee-verify", "aee", "observedeffect"]
CLI_FLAGS = ["--corpus", "--verifier", "--report", "--list-corpora", "--jcs-byte-vectors", "--vectors"]
DISTRIBUTION = "agent-evidence-vectors"
CONSOLE_SCRIPT = "agent-evidence-vectors"
NPM_PACKAGES = {"jcs-admit"}
JCS_WHEEL = [
    "agent_evidence_vectors/corpora/corpora/jcs-byte-vectors/cases.json",
    "agent_evidence_vectors/corpora/corpora/jcs-byte-vectors/README.md",
]
#: Where the rail lives, in the order it is looked for.
RAILS = ["packaging/run_vectors.py", "src/agent_evidence_vectors/run_vectors.py"]


def action_names(text: str, section: str) -> list[str]:
    """Top-level keys of one section of action.yml, read without a YAML library."""
    names, inside = [], False
    for line in text.splitlines():
        if re.match(r"^\S", line):
            inside = line.rstrip() == f"{section}:"
            continue
        match = re.match(r"^  ([A-Za-z0-9_-]+):", line)
        if inside and match:
            names.append(match.group(1))
    return names


def wheel_corpus_paths(repo: Path) -> dict[str, str]:
    with open(repo / "corpora/REGISTRY.toml", "rb") as source:
        return {row["id"]: row["path"] for row in tomllib.load(source)["corpus"] if row["wheel"]}


def action_failures(repo: Path) -> list[str]:
    action = repo / "action.yml"
    if not action.is_file():
        return ["P1 action.yml is not at the repository root"]
    text = action.read_text(encoding="utf-8")
    fail = []
    for section, wanted in (("inputs", ACTION_INPUTS), ("outputs", ACTION_OUTPUTS)):
        have = set(action_names(text, section))
        fail += [f"P1 action.yml {section} no longer declares {name}" for name in wanted if name not in have]
    return fail


def corpus_failures(repo: Path) -> list[str]:
    fail = []
    shipped = wheel_corpus_paths(repo)
    for cid, who in PINNED_CORPORA.items():
        if cid not in shipped:
            fail.append(f"P2 corpus {cid} is not a wheel-shipped registry row ({who})")
        elif not (repo / shipped[cid] / "MANIFEST.json").is_file():
            fail.append(f"P2 corpus {cid}: {shipped[cid]}/MANIFEST.json is missing ({who})")
    if not (repo / "vectors" / "MANIFEST.json").is_file():
        fail.append("P3 vectors/MANIFEST.json is not at the repository root")
    return fail


def release_failures(repo: Path) -> list[str]:
    fail = []
    key = repo / "release/cosign.pub"
    if not key.is_file():
        fail.append("P4 release/cosign.pub is missing")
    elif hashlib.sha256(key.read_bytes()).hexdigest() != COSIGN_SHA256:
        fail.append("P4 release/cosign.pub no longer has the digest adopters pin")
    digests = repo / "release/CORPUS-DIGESTS.txt"
    if not digests.is_file():
        return fail + ["P5 release/CORPUS-DIGESTS.txt is missing"]
    listed = set()
    for line in digests.read_text(encoding="utf-8").splitlines():
        if line.startswith("#") or not line.strip():
            continue
        fields = line.split()
        match = re.fullmatch(r"(vectors(?:-[a-z0-9]+)*)/MANIFEST\.json", fields[1]) if len(fields) >= 4 else None
        if not (match and re.fullmatch(r"[0-9a-f]{64}", fields[0]) and re.fullmatch(r"vectors=\d+", fields[3])):
            fail.append(f"P5 digest list line is not <digest> <id>/MANIFEST.json <suite> vectors=<n>: {line[:90]}")
            continue
        listed.add(match.group(1))
    fail += [f"P5 digest list has no line for {cid}/MANIFEST.json" for cid in PINNED_CORPORA if cid not in listed]
    release_yml = (repo / ".github/workflows/release.yml").read_text(encoding="utf-8")
    fail += [f"P6 release.yml no longer names the release asset {a}" for a in RELEASE_ASSETS if a not in release_yml]
    return fail


def go_failures(repo: Path) -> list[str]:
    fail = []
    if not re.search(rf"^module {re.escape(GO_MODULE)}$", (repo / "go.mod").read_text(encoding="utf-8"), re.M):
        fail.append(f"P7 go.mod module path is not {GO_MODULE}")
    for package in GO_PACKAGES:
        if not list((repo / package).glob("*.go")):
            fail.append(f"P7 Go package {package} has no .go files")
    sources = "\n".join(p.read_text(encoding="utf-8") for p in (repo / "cmd/aee-verify").glob("*.go"))
    if not re.search(r"^package main$", sources, re.M):
        fail.append("P7 cmd/aee-verify is not a main package")
    return fail


def cli_failures(repo: Path) -> list[str]:
    fail = []
    project = tomllib.loads((repo / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    if project["name"] != DISTRIBUTION:
        fail.append(f"P8 distribution name is not {DISTRIBUTION}")
    if CONSOLE_SCRIPT not in project.get("scripts", {}):
        fail.append(f"P8 console script {CONSOLE_SCRIPT} is not declared")
    rail = next((repo / r for r in RAILS if (repo / r).is_file()), None)
    if rail is None:
        return fail + ["P8 the rail run_vectors.py is not at " + " or ".join(RAILS)]
    result = subprocess.run([sys.executable, str(rail), "--help"], capture_output=True, text=True, timeout=120)
    if result.returncode != 0:
        return fail + [f"P8 {rail.relative_to(repo)} --help exited {result.returncode}"]
    fail += [f"P8 the command line no longer offers {flag}" for flag in CLI_FLAGS if flag not in result.stdout]
    return fail


def metadata_failures(repo: Path) -> list[str]:
    fail = [f"P9 {name} is not at the repository root" for name in ("CITATION.cff", ".zenodo.json")
            if not (repo / name).is_file()]
    tracked = subprocess.run(["git", "-C", str(repo), "ls-files", "*package.json"],
                             capture_output=True, text=True, check=True).stdout.split()
    for rel in tracked:
        data = json.loads((repo / rel).read_text(encoding="utf-8"))
        if data.get("name") in NPM_PACKAGES:
            directory = (data.get("repository") or {}).get("directory")
            here = str(Path(rel).parent.as_posix())
            if directory != here:
                fail.append(f"P10 npm {data['name']} repository.directory is {directory}; the package is at {here}")
    return fail


def wheel_failures(wheel: Path) -> list[str]:
    fail = []
    with zipfile.ZipFile(wheel) as archive:
        names = set(archive.namelist())
        fail += [f"W1 wheel lacks agent_evidence_vectors/corpora/{cid}/MANIFEST.json" for cid in PINNED_CORPORA
                 if f"agent_evidence_vectors/corpora/{cid}/MANIFEST.json" not in names]
        fail += [f"W2 wheel lacks {path}" for path in JCS_WHEEL if path not in names]
        entry = next((n for n in names if n.endswith(".dist-info/entry_points.txt")), None)
        scripts = configparser.ConfigParser()
        if entry:
            scripts.read_string(archive.read(entry).decode("utf-8"))
        if not (scripts.has_section("console_scripts") and CONSOLE_SCRIPT in scripts["console_scripts"]):
            fail.append(f"W3 wheel declares no console script {CONSOLE_SCRIPT}")
    return fail


def main() -> int:
    parser = argparse.ArgumentParser(description="Check that every name and path an adopter pins still resolves.")
    parser.add_argument("--wheel", type=Path, help="also check this built wheel")
    parser.add_argument("--repo", type=Path, default=REPO, help=argparse.SUPPRESS)
    args = parser.parse_args()
    fail = []
    for check in (action_failures, corpus_failures, release_failures, go_failures, cli_failures, metadata_failures):
        fail += check(args.repo)
    if args.wheel:
        fail += wheel_failures(args.wheel)
    for line in fail:
        print(f"FAIL: {line}")
    print(f"adopter pins ({'tree and wheel' if args.wheel else 'tree'}): {len(fail)} failed")
    return 1 if fail else 0


if __name__ == "__main__":
    raise SystemExit(main())
