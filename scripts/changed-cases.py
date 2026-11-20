#!/usr/bin/env python3
"""List the conformance cases that changed between two revisions, and hold semver to it.

A consumer pins one release of this corpus, exactly, and Dependabot opens a bump pull
request for the next one. What that consumer needs to read in the bump is which cases
were added, changed or removed, corpus by corpus, because each of those can turn a
verifier that passed red. GitHub's generated notes list merged pull requests, and a
pull request title does not say which case ids it touched. So this script reads every
corpus manifest at both revisions from the object store and diffs the cases.

A case is one member of a manifest's case list (`vectors`, `members`, `cases` or
`conditions`), named by its `id` (or `path`, or `name`). Its fingerprint is the member's
canonical JSON together with the object id of every file or directory the member names
(`file`, `files`, `path`, `dir`, `record`, `sidecar`, `manifest`, `signature`, `twin`,
`document`), so a case whose bytes changed under an unchanged manifest entry still
counts as changed. A packaged corpus whose manifest maps member files to digests
(`packaging/agent_evidence_vectors/<suite>/corpus/manifest.json`) contributes the cases
of each member that holds a `cases` list, and the member file itself otherwise. A
change to a manifest's other fields (its contract, its counts aside) is reported as a
contract change, because it can move a verdict without touching any case.

Three subcommands:

  diff   --from REV --to REV [--json]   the table, or the JSON
  notes  --from REV --to REV             the Markdown section for a release body
  semver --version X.Y.Z [--to REV] [--from REV]
         refuse (exit 1) a patch version whose diff adds, changes or removes a case
         or changes a corpus contract; --from defaults to the highest vX.Y.Z tag
         below the version

Exit 0 on success, 1 on a semver refusal, 2 when a manifest or revision cannot be read.
A manifest this script cannot read as a case list is an error, never an empty corpus.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent

MANIFEST_PATTERNS = (
    re.compile(r"^corpora/[^/]+/MANIFEST\.json$"),
    re.compile(r"^vectors[^/]*/MANIFEST\.json$"),
    re.compile(r"^packaging/agent_evidence_vectors/[^/]+/corpus/(?:MANIFEST|manifest)\.json$"),
)
CASE_LIST_KEYS = ("vectors", "members", "cases", "conditions")
CASE_NAME_KEYS = ("id", "path", "name")
REFERENCE_KEYS = ("file", "files", "path", "dir", "record", "sidecar", "manifest",
                  "signature", "twin", "document")
# Fields every manifest recomputes from its members. A change in them follows a case
# change and is not a separate contract change.
DERIVED_KEYS = frozenset({"corpusDigest", "counts", *CASE_LIST_KEYS})
TAG_RE = re.compile(r"^v(\d+)\.(\d+)\.(\d+)$")


class ReadError(Exception):
    """A revision, a manifest or a member could not be read as this script expects."""


def git(repo: Path, *args: str) -> str:
    proc = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True)
    if proc.returncode != 0:
        raise ReadError(f"git {' '.join(args)}: {proc.stderr.strip() or 'failed'}")
    return proc.stdout


def git_bytes(repo: Path, rev: str, path: str) -> bytes:
    proc = subprocess.run(["git", "-C", str(repo), "show", f"{rev}:{path}"], capture_output=True)
    if proc.returncode != 0:
        raise ReadError(f"{rev}:{path} cannot be read: {proc.stderr.decode().strip()}")
    return proc.stdout


def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


@dataclass
class Corpus:
    path: str
    name: str
    cases: dict[str, str] = field(default_factory=dict)
    contract: str = ""


def manifests_at(repo: Path, rev: str) -> list[str]:
    names = git(repo, "ls-tree", "-r", "--name-only", rev).splitlines()
    return sorted(n for n in names if any(p.match(n) for p in MANIFEST_PATTERNS))


def object_ids(repo: Path, rev: str, base: str, refs: list[str]) -> dict[str, str]:
    """Object id of each referenced path, or "missing", read in one git call."""
    if not refs:
        return {}
    specs = [f"{rev}:{(Path(base) / ref).as_posix()}" for ref in refs]
    proc = subprocess.run(["git", "-C", str(repo), "cat-file", "--batch-check"],
                          input="\n".join(specs) + "\n", capture_output=True, text=True)
    if proc.returncode != 0:
        raise ReadError(f"git cat-file --batch-check: {proc.stderr.strip()}")
    out: dict[str, str] = {}
    for ref, line in zip(refs, proc.stdout.splitlines(), strict=True):
        out[ref] = "missing" if line.endswith(" missing") else line.split()[0]
    return out


def references(entry: dict[str, Any]) -> list[str]:
    refs: list[str] = []
    for key in REFERENCE_KEYS:
        value = entry.get(key)
        if isinstance(value, str):
            refs.append(value)
        elif isinstance(value, list):
            refs.extend(v for v in value if isinstance(v, str))
        elif isinstance(value, dict):
            refs.extend(v for v in value.values() if isinstance(v, str))
    return sorted(set(r for r in refs if r and not r.startswith(("http:", "https:"))))


def case_name(entry: dict[str, Any], where: str) -> str:
    for key in CASE_NAME_KEYS:
        value = entry.get(key)
        if isinstance(value, str) and value:
            return value
    raise ReadError(f"{where}: a case has none of {CASE_NAME_KEYS}")


def list_cases(repo: Path, rev: str, base: str, entries: list[Any], where: str) -> dict[str, str]:
    cases: dict[str, str] = {}
    pending: list[tuple[str, dict[str, Any], list[str]]] = []
    all_refs: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict):
            raise ReadError(f"{where}: a case is not an object")
        name = case_name(entry, where)
        if name in cases or any(name == p[0] for p in pending):
            raise ReadError(f"{where}: case {name!r} appears twice")
        refs = references(entry)
        all_refs.update(refs)
        pending.append((name, entry, refs))
    oids = object_ids(repo, rev, base, sorted(all_refs))
    for name, entry, refs in pending:
        blob = canonical(entry) + "".join(f"\n{r}={oids[r]}" for r in refs)
        cases[name] = hashlib.sha256(blob.encode()).hexdigest()
    return cases


def member_cases(
    repo: Path, rev: str, base: str, members: dict[str, Any], where: str
) -> dict[str, str]:
    cases: dict[str, str] = {}
    for member, digest in sorted(members.items()):
        held = None
        if member.endswith(".json"):
            try:
                held = json.loads(git_bytes(repo, rev, f"{base}/{member}"))
            except ReadError:
                held = None
            except ValueError as err:
                raise ReadError(f"{where}: member {member} is not JSON: {err}") from err
        if isinstance(held, dict) and isinstance(held.get("cases"), list):
            for name, fp in list_cases(repo, rev, base, held["cases"], f"{where}:{member}").items():
                cases[f"{member}#{name}"] = fp
        else:
            cases[member] = canonical(digest)
    return cases


def read_corpus(repo: Path, rev: str, manifest_path: str) -> Corpus:
    try:
        manifest = json.loads(git_bytes(repo, rev, manifest_path))
    except ValueError as err:
        raise ReadError(f"{rev}:{manifest_path} is not JSON: {err}") from err
    if not isinstance(manifest, dict):
        raise ReadError(f"{rev}:{manifest_path} is not an object")
    base = str(Path(manifest_path).parent)
    suite = manifest.get("suite")
    corpus = Corpus(path=base, name=suite if isinstance(suite, str) and suite else base)
    where = f"{rev}:{manifest_path}"
    for key in CASE_LIST_KEYS:
        value = manifest.get(key)
        if isinstance(value, list) and value:
            corpus.cases = list_cases(repo, rev, base, value, where)
            break
        if isinstance(value, dict) and value:
            corpus.cases = member_cases(repo, rev, base, value, where)
            break
    else:
        raise ReadError(f"{where}: no case list under any of {CASE_LIST_KEYS}")
    corpus.contract = canonical({k: v for k, v in manifest.items() if k not in DERIVED_KEYS})
    return corpus


def read_all(repo: Path, rev: str) -> dict[str, Corpus]:
    return {c.path: c for c in (read_corpus(repo, rev, m) for m in manifests_at(repo, rev))}


def diff(repo: Path, old: str, new: str) -> dict[str, Any]:
    before, after = read_all(repo, old), read_all(repo, new)
    rows: list[dict[str, Any]] = []
    for path in sorted(set(before) | set(after)):
        was, now = before.get(path), after.get(path)
        named = now or was
        old_cases = was.cases if was else {}
        new_cases = now.cases if now else {}
        row = {
            "corpus": named.name if named else path,
            "path": path,
            "status": "added" if was is None else ("removed" if now is None else "kept"),
            "added": sorted(set(new_cases) - set(old_cases)),
            "removed": sorted(set(old_cases) - set(new_cases)),
            "changed": sorted(k for k in set(old_cases) & set(new_cases)
                              if old_cases[k] != new_cases[k]),
            "contractChanged": bool(was and now and was.contract != now.contract),
            "cases": len(new_cases),
        }
        if row["status"] != "kept" or row["added"] or row["removed"] or row["changed"] \
                or row["contractChanged"]:
            rows.append(row)
    totals = {k: sum(len(r[k]) for r in rows) for k in ("added", "changed", "removed")}
    totals["contractChanged"] = sum(1 for r in rows if r["contractChanged"])
    return {
        "from": old, "to": new,
        "fromCommit": git(repo, "rev-parse", f"{old}^{{commit}}").strip(),
        "toCommit": git(repo, "rev-parse", f"{new}^{{commit}}").strip(),
        "corporaRead": {"from": len(before), "to": len(after)},
        "corpora": rows, "totals": totals,
    }


def case_changes(result: dict[str, Any]) -> bool:
    t = result["totals"]
    return bool(t["added"] or t["changed"] or t["removed"] or t["contractChanged"])


def render_notes(result: dict[str, Any]) -> str:
    t = result["totals"]
    lines = [
        "## Cases that changed",
        "",
        f"Between `{result['from']}` and `{result['to']}`, read from every corpus manifest "
        f"({result['corporaRead']['from']} at `{result['from']}`, "
        f"{result['corporaRead']['to']} at `{result['to']}`): "
        f"{t['added']} added, {t['changed']} changed, {t['removed']} removed, "
        f"{t['contractChanged']} corpus contracts changed.",
        "",
    ]
    if not result["corpora"]:
        lines.append("No case was added, changed or removed.")
        return "\n".join(lines) + "\n"
    lines += ["| Corpus | Added | Changed | Removed | Contract |",
              "| --- | --- | --- | --- | --- |"]
    for row in result["corpora"]:
        name = row["corpus"] + ("" if row["status"] == "kept" else f" ({row['status']} corpus)")
        lines.append(f"| `{name}` | {len(row['added'])} | {len(row['changed'])} | "
                     f"{len(row['removed'])} | {'changed' if row['contractChanged'] else '-'} |")
    for row in result["corpora"]:
        if not (row["added"] or row["changed"] or row["removed"]):
            continue
        lines += ["", f"### `{row['corpus']}`", ""]
        for kind in ("added", "changed", "removed"):
            for case in row[kind]:
                lines.append(f"- {kind}: `{case}`")
    lines += ["", f"Generated by `scripts/changed-cases.py notes --from {result['from']} "
              f"--to {result['to']}`."]
    return "\n".join(lines) + "\n"


def parse_version(text: str) -> tuple[int, int, int]:
    match = TAG_RE.match(text if text.startswith("v") else f"v{text}")
    if not match:
        raise ReadError(f"{text!r} is not a version of the form X.Y.Z")
    return int(match[1]), int(match[2]), int(match[3])


def previous_tag(repo: Path, version: tuple[int, int, int]) -> str:
    tags = [t for t in git(repo, "tag", "--list", "v*").split() if TAG_RE.match(t)]
    lower = sorted((parse_version(t), t) for t in tags if parse_version(t) < version)
    if not lower:
        raise ReadError(f"no vX.Y.Z tag below v{'.'.join(map(str, version))}")
    return lower[-1][1]


def semver(repo: Path, version_text: str, new: str, old: str | None) -> int:
    version = parse_version(version_text)
    old = old or previous_tag(repo, version)
    prior = parse_version(old)
    result = diff(repo, old, new)
    t = result["totals"]
    summary = (f"{t['added']} added, {t['changed']} changed, {t['removed']} removed, "
               f"{t['contractChanged']} contracts changed")
    is_patch = version[:2] == prior[:2] and version[2] > prior[2]
    if is_patch and case_changes(result):
        print(f"refused: v{version_text.lstrip('v')} is a patch release after {old}, and the "
              f"cases changed ({summary}). A case that can turn a passing verifier red ships "
              f"in a minor release: bump to v{version[0]}.{version[1] + 1}.0.")
        return 1
    kind = "patch" if is_patch else ("minor or major" if version > prior else "not above")
    if version <= prior:
        print(f"refused: v{version_text.lstrip('v')} is not above {old}")
        return 1
    print(f"ok: v{version_text.lstrip('v')} is a {kind} release after {old} ({summary})")
    return 0


def print_table(result: dict[str, Any]) -> None:
    for row in result["corpora"]:
        for kind in ("added", "changed", "removed"):
            for case in row[kind]:
                print(f"{kind}\t{row['corpus']}\t{case}")
        if row["contractChanged"]:
            print(f"contract\t{row['corpus']}\t-")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument("--repo", type=Path, default=REPO_ROOT)
    sub = parser.add_subparsers(dest="cmd", required=True)
    for name in ("diff", "notes"):
        p = sub.add_parser(name)
        p.add_argument("--from", dest="old", required=True)
        p.add_argument("--to", dest="new", default="HEAD")
        if name == "diff":
            p.add_argument("--json", action="store_true")
    p = sub.add_parser("semver")
    p.add_argument("--version", required=True)
    p.add_argument("--to", dest="new", default="HEAD")
    p.add_argument("--from", dest="old", default=None)
    args = parser.parse_args(argv)
    try:
        if args.cmd == "semver":
            return semver(args.repo, args.version, args.new, args.old)
        result = diff(args.repo, args.old, args.new)
    except ReadError as err:
        print(f"changed-cases: {err}", file=sys.stderr)
        return 2
    if args.cmd == "notes":
        sys.stdout.write(render_notes(result))
    elif args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print_table(result)
    return 0


if __name__ == "__main__":
    sys.exit(main())
