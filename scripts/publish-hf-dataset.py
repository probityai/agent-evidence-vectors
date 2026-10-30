#!/usr/bin/env python3
"""Build, check and publish the Hugging Face copy of one corpus release.

The dataset at huggingface.co/datasets/probityai/agent-evidence-vectors is a
copy of a tagged release of this repository, and the copy has to follow the
tag. The script that first built the copy was not kept, so this one is the
record of how it is built, and a test rebuilds the first copy (v0.25.0) and
requires the same bytes.

What the dataset holds, all taken from the tag and nothing from a branch:

  * every file of every top-level directory named `vectors` or `vectors-*`
    that has a MANIFEST.json directly inside it, at the same paths;
  * `release/`, the maintainer-signed digest list with its timestamps;
  * `LICENSE` and `CITATION.cff`;
  * `data/cases.jsonl`, one row per manifest entry, and `data/corpora.jsonl`,
    one row per corpus, both derived from the manifests in the tree;
  * a dataset card `README.md` whose numbers are counted from that data,
    `SOURCE.json` (the tag, the commit and the checks that ran) and
    `SHA256SUMS` (every file above except itself, `sha256sum -c` format).

Modes:

    build  --tag vX.Y.Z --out DIR   check the tag, then write the tree
    check  DIR                      re-hash and re-derive a built tree
    upload DIR --tag vX.Y.Z         replace the dataset tree in one commit,
                                    tag it, read the tag back

`build` runs the two release checks SOURCE.json records, in a checkout of the
tag, and fails when either does not pass or cannot run: `release-digests.py
--check` and `cosign verify-blob` of release/CORPUS-DIGESTS.txt against
release/cosign.pub (docs/reference/release-verification.md). A missing cosign
is a failure, never a skip.

`upload` calls the `hf` command and reads the token from HF_TOKEN. Only the
tag it is given is ever published, so a re-run for the same tag repeats the
same bytes.

Exit 0 on success, 1 on any failure.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from collections.abc import Iterator
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
DATASET = "probityai/agent-evidence-vectors"
HF_API = "https://huggingface.co/api/datasets/"
HF_RAW = "https://huggingface.co/datasets/"

TAG_RE = re.compile(r"v\d+\.\d+\.\d+")
CORPUS_DIR_RE = re.compile(r"vectors(-[^/]+)?")
ROOT_FILES = ("LICENSE", "CITATION.cff")
RELEASE_DIR = "release"
DIGESTS = "release/CORPUS-DIGESTS.txt"
SIGNATURE = "release/CORPUS-DIGESTS.txt.sig"
PUBLIC_KEY = "release/cosign.pub"
MANIFEST = "MANIFEST.json"

# Files this script writes. Everything else in a built tree comes from the tag.
CARD = "README.md"
SOURCE = "SOURCE.json"
SUMS = "SHA256SUMS"
CASES = "data/cases.jsonl"
CORPORA = "data/corpora.jsonl"
GENERATED = (CARD, SOURCE, CASES, CORPORA)

# Recorded in SOURCE.json: the checks `build` ran before it wrote anything.
CHECKS = ["release-digests.py --check", "cosign verify-blob release/cosign.pub"]

REGULAR_MODES = frozenset({"100644", "100755"})

# Patterns for the files an upload replaces. The dataset's own .gitattributes is
# created by the Hub and is not ours, so it is not named here.
DELETE_PATTERNS = ["data/*", "release/*", "vectors/*", "vectors-*/*"]


class PublishError(Exception):
    """A build, check or upload step failed, with the reason."""


# ---------------------------------------------------------------- git access


def git(repo: Path, *args: str, data: bytes | None = None) -> bytes:
    """Run one git command in `repo` and return its stdout."""
    proc = subprocess.run(
        ["git", "-C", str(repo), *args], input=data, capture_output=True, check=False
    )
    if proc.returncode != 0:
        raise PublishError(f"git {' '.join(args)} failed: {proc.stderr.decode(errors='replace')}")
    return proc.stdout


def resolve_tag(repo: Path, tag: str) -> str:
    """The commit a corpus release tag names."""
    if not TAG_RE.fullmatch(tag):
        raise PublishError(f"{tag!r} is not a corpus release tag (vMAJOR.MINOR.PATCH)")
    return git(repo, "rev-parse", "--verify", f"refs/tags/{tag}^{{commit}}").decode().strip()


def list_tree(repo: Path, commit: str) -> dict[str, tuple[str, str]]:
    """Every path of the commit's tree: path -> (mode, blob id)."""
    raw = git(repo, "ls-tree", "-r", "-z", "--full-tree", commit)
    tree: dict[str, tuple[str, str]] = {}
    for record in raw.split(b"\0"):
        if not record:
            continue
        meta, path = record.split(b"\t", 1)
        mode, kind, blob = meta.decode().split(" ")
        if kind != "blob":
            raise PublishError(f"{path.decode()!r} is a {kind}; only plain files are published")
        tree[path.decode()] = (mode, blob)
    return tree


def read_blobs(repo: Path, blobs: list[str]) -> Iterator[bytes]:
    """The bytes of each blob, in order, through one `git cat-file --batch`."""
    proc = subprocess.Popen(
        ["git", "-C", str(repo), "cat-file", "--batch"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
    )
    assert proc.stdin is not None and proc.stdout is not None
    try:
        for blob in blobs:
            proc.stdin.write(blob.encode() + b"\n")
            proc.stdin.flush()
            header = proc.stdout.readline().split()
            if len(header) != 3 or header[1] != b"blob":
                raise PublishError(f"git cat-file could not read {blob}")
            body = proc.stdout.read(int(header[2]) + 1)
            yield body[:-1]
    finally:
        proc.stdin.close()
        proc.stdout.close()
        proc.wait()


# ------------------------------------------------------------ file selection


def corpus_dirs(paths: list[str]) -> list[str]:
    """Top-level directories named vectors or vectors-* with a MANIFEST.json."""
    present = set(paths)
    tops = {p.split("/", 1)[0] for p in paths if "/" in p}
    named = (t for t in tops if CORPUS_DIR_RE.fullmatch(t))
    return sorted(t for t in named if f"{t}/{MANIFEST}" in present)


def select_files(tree: dict[str, tuple[str, str]]) -> tuple[list[str], list[str]]:
    """The corpus directories and the paths the dataset takes, in publication order."""
    corpora = corpus_dirs(list(tree))
    prefixes = tuple(f"{c}/" for c in corpora) + (f"{RELEASE_DIR}/",)
    picked = [p for p in tree if p.startswith(prefixes) or p in ROOT_FILES]
    missing = [f for f in ROOT_FILES if f not in tree]
    if missing:
        raise PublishError(f"the tag has no {', '.join(missing)}")
    for path in picked:
        if tree[path][0] not in REGULAR_MODES:
            raise PublishError(f"{path} has mode {tree[path][0]}; only regular files are published")
    return corpora, sorted(picked, key=lambda p: tuple(p.split("/")))


def signed_digests(text: str) -> dict[str, str]:
    """manifest path -> corpus digest, from release/CORPUS-DIGESTS.txt."""
    out: dict[str, str] = {}
    for line in text.splitlines():
        if line and not line.startswith("#"):
            fields = line.split()
            out[fields[1]] = fields[0]
    return out


# ------------------------------------------------------------- release checks


@contextlib.contextmanager
def checkout(repo: Path, commit: str) -> Iterator[Path]:
    """A detached checkout of `commit`, removed afterwards."""
    parent = Path(tempfile.mkdtemp(prefix="aev-hf-checkout-"))
    root = parent / "tree"
    git(repo, "worktree", "add", "--detach", str(root), commit)
    try:
        yield root
    finally:
        subprocess.run(
            ["git", "-C", str(repo), "worktree", "remove", "--force", str(root)],
            capture_output=True,
            check=False,
        )
        shutil.rmtree(parent, ignore_errors=True)


def run_release_checks(root: Path, python: str, cosign: str | None) -> None:
    """Run the two checks SOURCE.json records, in a checkout of the tag."""
    found = shutil.which(cosign) if cosign else shutil.which("cosign")
    if found is None:
        raise PublishError("cosign is not installed, so the release signature cannot be checked")
    steps = [
        ([python, "scripts/release-digests.py", "--check"], CHECKS[0]),
        (
            [
                found,
                "verify-blob",
                "--key",
                PUBLIC_KEY,
                "--signature",
                SIGNATURE,
                "--insecure-ignore-tlog=true",
                DIGESTS,
            ],
            CHECKS[1],
        ),
    ]
    for command, name in steps:
        proc = subprocess.run(command, cwd=root, capture_output=True, text=True, check=False)
        if proc.returncode != 0:
            raise PublishError(f"release check failed: {name}\n{proc.stdout}{proc.stderr}")
        print(f"ok: {name}")


# ------------------------------------------------------------- data derivation


def _no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    keys = [k for k, _v in pairs]
    dup = sorted({k for k in keys if keys.count(k) > 1})
    if dup:
        raise PublishError(f"duplicate JSON keys {dup}")
    return dict(pairs)


def load_manifest(path: Path) -> dict[str, Any]:
    """A corpus manifest, refusing duplicate keys and a missing `vectors` list."""
    try:
        doc = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_no_duplicate_keys)
    except (OSError, ValueError, PublishError) as exc:
        raise PublishError(f"{path}: {exc}") from exc
    if not isinstance(doc, dict) or not isinstance(doc.get("vectors"), list):
        raise PublishError(f"{path}: no `vectors` list")
    for key in ("corpusDigest", "suite"):
        if not isinstance(doc.get(key), str):
            raise PublishError(f"{path}: no string `{key}`")
    return doc


def case_id(entry: dict[str, Any]) -> str:
    """The identifier of one manifest entry.

    Almost every corpus names it `id`. The a2a-jcs corpus lists only `path` and
    `sha256`, and its files are named by case, so the file's stem is the id.
    """
    if isinstance(entry.get("id"), str):
        return str(entry["id"])
    path = entry.get("path")
    if "id" not in entry and isinstance(path, str):
        return Path(path).stem
    raise PublishError(f"manifest entry has no usable id: {sorted(entry)}")


def entry_path(entry: dict[str, Any]) -> str | None:
    """The file or directory an entry names, or None when it names none.

    Entries key their payload as `file`, as `path` (a file or a `cases/<name>`
    directory), or by some other key (`record`, `manifest`, `stream`, a sidecar)
    that this column does not carry; those rows have a null path.
    """
    for key in ("file", "path"):
        if isinstance(entry.get(key), str):
            return str(entry[key])
    return None


def derive_case(corpus: str, manifest: dict[str, Any], entry: Any) -> dict[str, Any]:
    """One row of data/cases.jsonl."""
    if not isinstance(entry, dict):
        raise PublishError(f"{corpus}: a manifest entry is not an object")
    path = entry_path(entry)
    expected = entry.get("expected")
    revision = manifest.get("suiteRevision")
    return {
        "case_id": case_id(entry),
        "corpus": corpus,
        "corpus_digest": manifest["corpusDigest"],
        "entry": json.dumps(entry, sort_keys=True),
        "expected": None if expected is None else json.dumps(expected, sort_keys=True),
        "kind": entry.get("kind"),
        "path": None if path is None else f"{corpus}/{path}",
        "suite": manifest["suite"],
        "suite_revision": None if revision is None else str(revision),
    }


def derive_corpus(corpus: str, manifest: dict[str, Any]) -> dict[str, Any]:
    """One row of data/corpora.jsonl."""
    revision = manifest.get("suiteRevision")
    return {
        "corpus": corpus,
        "corpus_digest": manifest["corpusDigest"],
        "manifest": f"{corpus}/{MANIFEST}",
        "suite": manifest["suite"],
        "suite_revision": None if revision is None else str(revision),
        "vectors": len(manifest["vectors"]),
    }


def derive_rows(root: Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """(cases, corpora) from the manifests of the corpus directories under root.

    Corpora are ordered by manifest path (so `vectors/` comes after `vectors-*`,
    as in the first copy) and cases keep each manifest's own order.
    """
    names = sorted(
        (
            p.name
            for p in root.iterdir()
            if p.is_dir() and CORPUS_DIR_RE.fullmatch(p.name) and (p / MANIFEST).is_file()
        ),
        key=lambda n: f"{n}/{MANIFEST}",
    )
    cases: list[dict[str, Any]] = []
    corpora: list[dict[str, Any]] = []
    for name in names:
        manifest = load_manifest(root / name / MANIFEST)
        corpora.append(derive_corpus(name, manifest))
        rows = [derive_case(name, manifest, e) for e in manifest["vectors"]]
        ids = [r["case_id"] for r in rows]
        if len(set(ids)) != len(ids):
            raise PublishError(f"{name}: repeated case ids")
        cases.extend(rows)
    return cases, corpora


def jsonl(rows: list[dict[str, Any]]) -> bytes:
    """Rows as JSON lines, keys sorted, one per line."""
    return "".join(json.dumps(r, sort_keys=True) + "\n" for r in rows).encode()


# ------------------------------------------------------------------ the card

CARD_TEMPLATE = HERE / "hf-dataset-card.tmpl"


def size_category(rows: int) -> str:
    """The Hub's size bucket for a row count."""
    bounds = [(1_000, "n<1K"), (10_000, "1K<n<10K"), (100_000, "10K<n<100K")]
    return next((label for limit, label in bounds if rows < limit), "100K<n<1M")


def citation_field(text: str, key: str) -> str:
    """A top-level scalar of CITATION.cff."""
    match = re.search(rf"^{re.escape(key)}:\s*(\S+)\s*$", text, re.MULTILINE)
    if match is None:
        raise PublishError(f"CITATION.cff has no top-level {key}")
    return match.group(1)


def render_card(source: dict[str, Any], doi: str, first_expected: str) -> str:
    """The dataset card, every number taken from `source` and the data."""
    repository = str(source["repository"])
    tag = str(source["tag"])
    return CARD_TEMPLATE.read_text(encoding="utf-8").format(
        size=size_category(int(source["cases"])),
        cases=source["cases"],
        corpora=source["corpora"],
        tag=tag,
        version=tag[1:],
        repository=repository,
        slug=repository.removeprefix("https://github.com/"),
        commit=source["commit"],
        dataset=DATASET,
        first_expected=first_expected,
        doi=doi,
    )


def first_expected(cases: list[dict[str, Any]]) -> str:
    """The verdict the card prints: the first case of the `vectors` corpus."""
    for row in cases:
        if row["corpus"] == "vectors" and isinstance(row["expected"], str):
            return str(row["expected"])
    raise PublishError("the `vectors` corpus has no first case with an expected verdict")


def render_source(
    repository: str, tag: str, commit: str, corpora: int, cases: int, files: int
) -> str:
    """SOURCE.json."""
    doc = {
        "repository": repository,
        "tag": tag,
        "commit": commit,
        "corpora": corpora,
        "cases": cases,
        "files_from_tag": files,
        "checks": CHECKS,
    }
    return json.dumps(doc, indent=2) + "\n"


def sums_text(digests: dict[str, str]) -> str:
    """SHA256SUMS, sha256sum -c format, ordered by path component."""
    ordered = sorted(digests, key=lambda p: tuple(p.split("/")))
    return "".join(f"{digests[p]}  {p}\n" for p in ordered)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ------------------------------------------------------------------- build


def write_file(out: Path, rel: str, data: bytes) -> None:
    target = out / rel
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(data)


def materialize(repo: Path, tree: dict[str, tuple[str, str]], paths: list[str], out: Path) -> None:
    """Write the selected blobs under `out`, byte for byte."""
    for path, data in zip(paths, read_blobs(repo, [tree[p][1] for p in paths]), strict=True):
        write_file(out, path, data)


def check_signed_list(out: Path, corpora: list[str]) -> None:
    """The signed digest list names exactly the corpora this tree publishes."""
    signed = signed_digests((out / DIGESTS).read_text(encoding="utf-8"))
    wanted = {f"{c}/{MANIFEST}" for c in corpora}
    if set(signed) != wanted:
        only_list = sorted(set(signed) - wanted)
        only_tree = sorted(wanted - set(signed))
        raise PublishError(
            f"{DIGESTS} and the corpus directories disagree: "
            f"only in the list {only_list}, only in the tree {only_tree}"
        )
    for corpus in corpora:
        manifest = load_manifest(out / corpus / MANIFEST)
        if signed[f"{corpus}/{MANIFEST}"] != manifest["corpusDigest"]:
            raise PublishError(f"{corpus}: the signed digest differs from the manifest's")


def write_derived(out: Path, tag: str, commit: str, files_from_tag: int) -> None:
    """Write data/*.jsonl, SOURCE.json and the card."""
    cases, corpora = derive_rows(out)
    write_file(out, CASES, jsonl(cases))
    write_file(out, CORPORA, jsonl(corpora))
    repository = citation_field(
        (out / "CITATION.cff").read_text(encoding="utf-8"), "repository-code"
    )
    source = render_source(repository, tag, commit, len(corpora), len(cases), files_from_tag)
    write_file(out, SOURCE, source.encode())
    doi = citation_field((out / "CITATION.cff").read_text(encoding="utf-8"), "doi")
    card = render_card(json.loads(source), doi, first_expected(cases))
    write_file(out, CARD, card.encode())


def write_sums(out: Path) -> None:
    """SHA256SUMS over every other file in the tree."""
    digests = {
        p.relative_to(out).as_posix(): sha256(p.read_bytes())
        for p in out.rglob("*")
        if p.is_file() and p.relative_to(out).as_posix() != SUMS
    }
    write_file(out, SUMS, sums_text(digests).encode())


def build(repo: Path, tag: str, out: Path, python: str, cosign: str | None) -> list[str]:
    """Check the tag, write the tree under `out`, and return the problems found."""
    commit = resolve_tag(repo, tag)
    if out.exists() and any(out.iterdir()):
        raise PublishError(f"{out} is not empty")
    tree = list_tree(repo, commit)
    corpora, paths = select_files(tree)
    with checkout(repo, commit) as root:
        run_release_checks(root, python, cosign)
    out.mkdir(parents=True, exist_ok=True)
    materialize(repo, tree, paths, out)
    check_signed_list(out, corpora)
    write_derived(out, tag, commit, len(paths))
    write_sums(out)
    return check_tree(out)


# ------------------------------------------------------------------- check


def parse_sums(text: str) -> dict[str, str]:
    """SHA256SUMS -> path: digest, refusing a line that is not `digest  path`."""
    out: dict[str, str] = {}
    for number, line in enumerate(text.splitlines(), 1):
        match = re.fullmatch(r"([0-9a-f]{64})  (\S.*)", line)
        if match is None or match.group(2) in out:
            raise PublishError(f"{SUMS} line {number} is not a unique `digest  path` line")
        out[match.group(2)] = match.group(1)
    return out


def tree_files(root: Path) -> set[str]:
    return {p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file()}


def check_hashes(root: Path) -> tuple[dict[str, str], list[str]]:
    """Every file hashes to its SHA256SUMS line, and no other file is present."""
    sums = parse_sums((root / SUMS).read_text(encoding="utf-8"))
    problems = []
    present = tree_files(root) - {SUMS}
    problems += [f"{p}: listed in {SUMS}, not present" for p in sorted(set(sums) - present)]
    problems += [f"{p}: present, not listed in {SUMS}" for p in sorted(present - set(sums))]
    for path in sorted(set(sums) & present):
        if sha256((root / path).read_bytes()) != sums[path]:
            problems.append(f"{path}: does not hash to its {SUMS} line")
    return sums, problems


def path_resolves(path: str, files: set[str], directories: set[str]) -> bool:
    return path in files or path in directories


def check_rows(root: Path, sums: dict[str, str]) -> list[str]:
    """Rows equal a fresh derivation from the tree's manifests, and each path resolves."""
    cases, corpora = derive_rows(root)
    problems = []
    if (root / CASES).read_bytes() != jsonl(cases):
        problems.append(f"{CASES} is not what the manifests in the tree derive")
    if (root / CORPORA).read_bytes() != jsonl(corpora):
        problems.append(f"{CORPORA} is not what the manifests in the tree derive")
    files = set(sums)
    directories = {d for f in files for d in _parents(f)}
    for row in cases:
        path = row["path"]
        if path is not None and not path_resolves(path, files, directories):
            problems.append(f"{row['corpus']}/{row['case_id']}: path {path} is not in the tree")
        if not isinstance(json.loads(row["entry"]), dict):
            problems.append(f"{row['corpus']}/{row['case_id']}: entry is not an object")
    return problems


def _parents(path: str) -> Iterator[str]:
    parts = path.split("/")[:-1]
    for i in range(1, len(parts) + 1):
        yield "/".join(parts[:i])


def check_counts(root: Path, sums: dict[str, str]) -> list[str]:
    """SOURCE.json and the card agree with the data and the file list."""
    problems = []
    source = json.loads((root / SOURCE).read_text(encoding="utf-8"))
    cases, corpora = derive_rows(root)
    expected_counts = {
        "corpora": len(corpora),
        "cases": len(cases),
        "files_from_tag": len(sums) - len(GENERATED),
    }
    for key, value in expected_counts.items():
        if source.get(key) != value:
            problems.append(f"{SOURCE} {key} is {source.get(key)!r}, the tree has {value}")
    if source.get("checks") != CHECKS:
        problems.append(f"{SOURCE} does not record the release checks")
    for row in corpora:
        counted = sum(1 for c in cases if c["corpus"] == row["corpus"])
        if counted != row["vectors"]:
            problems.append(f"{row['corpus']}: {counted} case rows for {row['vectors']} vectors")
    doi = citation_field((root / "CITATION.cff").read_text(encoding="utf-8"), "doi")
    card = render_card(source, doi, first_expected(cases))
    if (root / CARD).read_text(encoding="utf-8") != card:
        problems.append(f"{CARD} is not the card these numbers produce")
    return problems


def check_tree(root: Path) -> list[str]:
    """Every problem found in a built tree; empty when it is sound."""
    try:
        sums, problems = check_hashes(root)
        if problems:
            return problems
        return check_rows(root, sums) + check_counts(root, sums)
    except (OSError, ValueError, PublishError) as exc:
        return [str(exc)]


# ------------------------------------------------------------------ upload


def hf_json(url: str, token: str | None) -> Any:
    request = urllib.request.Request(url)
    if token:
        request.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(request, timeout=60) as response:
        return json.load(response)


def tag_action(refs: dict[str, Any], tag: str, head: str) -> str:
    """What to do about the dataset tag: `create`, `keep` or refuse by raising."""
    existing = {t["name"]: t["targetCommit"] for t in refs.get("tags", [])}
    if tag not in existing:
        return "create"
    if existing[tag] == head:
        return "keep"
    raise PublishError(
        f"dataset tag {tag} already points at {existing[tag]}, and main is at {head}; "
        "a published tag is never moved"
    )


def run_hf(*args: str, token: str) -> None:
    command = ["hf", *args]
    env = {**os.environ, "HF_TOKEN": token}
    proc = subprocess.run(command, env=env, check=False)
    if proc.returncode != 0:
        raise PublishError(f"`hf {args[0]}` failed with exit {proc.returncode}")


def upload_command(directory: Path, tag: str, commit: str) -> list[str]:
    """The `hf upload` arguments that replace the dataset tree in one commit."""
    args = ["upload", DATASET, str(directory), ".", "--repo-type", "dataset"]
    for pattern in DELETE_PATTERNS:
        args += ["--delete", pattern]
    return args + ["--commit-message", f"Mirror release {tag} ({commit[:12]})"]


def read_back(tag: str, directory: Path, token: str | None) -> None:
    """The tag, read from the Hub, serves the files that were built."""
    for name in (SUMS, SOURCE):
        url = f"{HF_RAW}{DATASET}/resolve/{tag}/{name}"
        request = urllib.request.Request(url)
        if token:
            request.add_header("Authorization", f"Bearer {token}")
        with urllib.request.urlopen(request, timeout=120) as response:
            served = response.read()
        if served != (directory / name).read_bytes():
            raise PublishError(f"{url} differs from the built {name}")
    print(f"ok: revision {tag} serves the built {SUMS} and {SOURCE}")


def upload(directory: Path, tag: str) -> None:
    """Replace the dataset tree, tag the commit, read the tag back."""
    token = os.environ.get("HF_TOKEN", "")
    if not token:
        raise PublishError("HF_TOKEN is not set; add it as a repository secret")
    problems = check_tree(directory)
    source = json.loads((directory / SOURCE).read_text(encoding="utf-8"))
    if problems or source["tag"] != tag:
        raise PublishError("; ".join(problems) or f"the tree was built for {source['tag']}")
    run_hf(*upload_command(directory, tag, source["commit"]), token=token)
    head = str(hf_json(f"{HF_API}{DATASET}/revision/main", token)["sha"])
    action = tag_action(hf_json(f"{HF_API}{DATASET}/refs", token), tag, head)
    if action == "create":
        message = f"Release {tag} of the source repository"
        run_hf(
            "repos",
            "tag",
            "create",
            DATASET,
            tag,
            "-m",
            message,
            "--repo-type",
            "dataset",
            token=token,
        )
    read_back(tag, directory, token)


# --------------------------------------------------------------------- main


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0] if __doc__ else "")
    sub = parser.add_subparsers(dest="mode", required=True)
    b = sub.add_parser("build", help="check a tag and write the dataset tree")
    b.add_argument("--tag", required=True)
    b.add_argument("--out", type=Path, required=True)
    b.add_argument("--repo", type=Path, default=REPO)
    b.add_argument("--cosign", default=None, help="path to the cosign binary")
    c = sub.add_parser("check", help="re-hash and re-derive a built tree")
    c.add_argument("directory", type=Path)
    u = sub.add_parser("upload", help="replace the dataset tree and tag it")
    u.add_argument("directory", type=Path)
    u.add_argument("--tag", required=True)
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    try:
        if args.mode == "build":
            problems = build(args.repo, args.tag, args.out, sys.executable, args.cosign)
        elif args.mode == "check":
            problems = check_tree(args.directory)
        else:
            upload(args.directory, args.tag)
            problems = []
    except (PublishError, urllib.error.URLError) as exc:
        print(f"publish-hf-dataset: {exc}", file=sys.stderr)
        return 1
    for problem in problems:
        print(f"publish-hf-dataset: {problem}", file=sys.stderr)
    if problems:
        return 1
    print(f"ok: {args.mode}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
