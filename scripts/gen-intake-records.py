#!/usr/bin/env python3
"""Write an intake record for every corpus this repository publishes.

    uv run --locked --extra generators python scripts/gen-intake-records.py
    uv run --locked --extra generators python scripts/gen-intake-records.py --check

The W3C public-agent-conformance group's intake criteria (v2, 2026Oct/0067,
with the deltas of 0070, 0073 and 0075) say what a submitted conformance
result must carry. This script submits every corpus listed in
``release/CORPUS-DIGESTS.txt`` that way: it RUNS the corpus's checker, twice
for the per-case output and once for the summary, keeps the native output
bytes under ``release/intake/native/``, and writes
``release/intake/<corpus directory>.intake.json`` from what the run printed,
never from what the manifest says the run should print. Each record is then
read by the intake checker (``agent_evidence_vectors.w3cintake``) with the
repository as its root, and a record the checker refuses stops the script.

What each record declares, and why it is true:

- The checker is ``aee-verify`` for every corpus but SCITT/COSE, which no Go
  reader here judges (it needs a CBOR decoder), so its record names
  ``vectors-scitt-cose/check_vectors.py``. The revision is a source listing
  over the checker's files, which any reader recomputes from the bytes; a
  change to any of them makes ``--check`` fail until the records are
  regenerated, because a record names the code that ran.
- The relationship to the reference implementation is ``same-implementation``:
  this repository's runner IS the reference. The expected answers were
  visible: every manifest carries them.
- ``non-author-runs`` carries the one re-run on the record by an operator who
  is not the author: github.com/DSHCorrectover/independent-reader, raised on
  the list in 2026Oct/0041, which read the reference source to derive its
  rules and imports none of it (reference-derived, no shared code). It ran
  against the corpora of release 0.17.6, so each entry carries that release's
  corpus digest and says whether it is the digest of the bytes recorded here.
- ``specification-readers`` names a reader written from the specification
  where one has run: the Rust reader of the v0.1 report, written from the
  text and the corpus, which shares no code path with the other two. It is
  ours, so it is not a non-author run.

- ``artifacts`` lists every tracked file of the corpus that is neither a member
  nor the manifest, pinned by its bytes and covered by the corpus digest, with
  the consumed state the swap-and-re-pin test of 2026Oct/0091 measures: the
  corpus is copied out, the file's bytes are replaced, every pin over it is
  moved (its sha256 wherever the corpus writes it, and the corpus digest
  through the corpus's own routine), and the checker runs again. A file whose
  swap leaves the complete native result byte for byte the baseline is
  ``unconsumed``, and its ``refused-by`` names the grounds the intake checker
  raises when it is swapped with its pin left in place.
- The anchor names the digest routine's file, and is a ``signed-digest-list``
  exactly when ``release/CORPUS-DIGESTS.txt`` verifies under
  ``release/cosign.pub`` with the signature beside it. A candidate tree's list
  has changed since the last release signed it, so its records name a located
  line and say in ``leaves-open`` that it is not a verified one; the release
  commit regenerates the records after signing (RELEASING.md).

``--check`` regenerates into memory and refuses any difference from the tree,
so a record cannot drift from the checker, the corpus or the run.
"""

from __future__ import annotations

import argparse
import functools
import hashlib
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "packaging"))

from agent_evidence_vectors import w3cintake  # noqa: E402

DIGESTS = "release/CORPUS-DIGESTS.txt"
SIGNATURE = DIGESTS + ".sig"
PUBLIC_KEY = "release/cosign.pub"
OUT = "release/intake"
NATIVE = OUT + "/native"
REPOSITORY = "https://github.com/probityai/agent-evidence-vectors"
GO_RUNTIME = "1.26"
PYTHON_RUNTIME = (3, 13)

#: The Go checker's source: the binary's package, every package it imports from
#: this module, and the module file. The module is stdlib-only, so there is no
#: go.sum; go.work decides which modules a build in this tree resolves.
GO_SOURCE = ["aee", "cmd/aee-verify", "corpora", "go.mod"]
GO_DEPENDENCIES = ["go.mod", "go.work"]
SCITT = "vectors-scitt-cose"
SCITT_SOURCE = [SCITT + "/check_vectors.py"]
PYTHON_DEPENDENCIES = ["pyproject.toml", "uv.lock"]

REFUSAL_VERDICTS = ["contradicted", "failed", "must-reject", "reject", "rejected"]
#: The fields of a manifest entry a refusal's rule is read from.
RULE_FIELDS = ("expected", "conditions", "requirements")

#: The corpus digests of release 0.17.6, read from the tag's
#: release/CORPUS-DIGESTS.txt (git show v0.17.6:release/CORPUS-DIGESTS.txt). The
#: re-run below was against that release's wheel; a digest here that differs
#: from the bytes recorded now means the re-run covered other bytes.
RELEASE_0176 = {
    "vectors-aci": "aa8deffa934df48d43f228e48e299be2a136aef32ff5a55d18a2ef99e0286740",
    "vectors-acs-core": "990cc18c1825ecd27cb33b6a68ebf5b5da2493d19e83791ef929b12b5bcad1cb",
    "vectors-agent-audit-record":
        "048ddde8c8ce7e65368c4c46bd91192765444d287b4fcd35c3260bfcf9bb80aa",
    "vectors-ai-agent-action": "36ab3447ae8a037ca30576209591cb0d0223b0539e64513c9c97ee0ed87288b5",
    "vectors-ai-generation": "786164241118262620eabae41936c62512c32a365bb3c2a94800df1cbf37f037",
    "vectors-anchor-stream": "6bc10ebd3b65776e96e78797101f85687437bcff89963864067795de2f2948be",
    "vectors-anchored-chain": "a92cf47c64f905ec6a57c4bf624c2667c075da4a76d58b4d251584831202dc86",
    "vectors-artifact-binding": "e26e5a50267f4f09052f3349388f703d0a332a41cf325a4d248e21414070cbef",
    "vectors-mcp-record-contract":
        "90ba5e8cc42aca0383fe76608b1648406a5824ed303c178dd40a22f1d8e36f26",
    "vectors-mcp-response-phase":
        "caa09e57af6e6ee85feff1fa5117095fa424c11a57a7518ca127d19676bfd5bc",
    "vectors-observed-effect": "1b45a2ea8023b019569fe5ef5489beca138bbe78229fd1f1c80fbae158f9dbaf",
    "vectors-receipt-signature": "cb490284f25c5eebc0a91c7776e6f195ae571c4f7dce029ae437128fce03a6ae",
    "vectors-scitt-cose": "79d651d3e127ce9bb68d4bf782f86b4e79391962ddda37f131fba641ca0c20da",
    "vectors-source-coverage": "1cb4748f8c2e4fd390a0a330d7631fed24023d927a612c32e8ee7b069472f9a3",
    "vectors-w3c-report": "f00d4443f14881b4102693da0b73ecc7524b7410aec25fe9dbef077e7f73f1fe",
    "vectors": "200f25888bafde0aee5f0f751d8c3282449aa25dda6fae2ae2473babb515690b",
}
INDEPENDENT_READER = "https://github.com/DSHCorrectover/independent-reader"
INDEPENDENT_REVISION = "e0e172f02457806a791c53481e7ecf76be12dc4d"
#: What the re-run's README reports per corpus (the table "Results against
#: v0.17.6"). The four named there were read against their full rules; the other
#: twelve corpora of that wheel at the structure and binding level, with the
#: corpus digest recomputed, and the README gives one total for those twelve.
INDEPENDENT_DEPTH = {
    "vectors-receipt-signature": ("full rules", "25/25 verdicts agree"),
    "vectors": ("full rules", "285/285 verdicts agree"),
    "vectors-w3c-report": ("full rules", "235/235 verdicts agree"),
    "vectors-anchored-chain": ("full rules", "14/14 verdicts agree"),
}
STRUCTURE_ONLY = ("structure and binding level, corpus digest recomputed",
                  "382/382 across the twelve corpora read at this depth; no per-corpus count "
                  "is published")


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read(rel: str) -> bytes:
    return (REPO / rel).read_bytes()


def corpora() -> list[tuple[str, str, str]]:
    """(corpus directory, suite, published digest) for every line of the digest list."""
    out = []
    for line in read(DIGESTS).decode("utf-8").split("\n"):
        if not line or line.startswith("#"):
            continue
        fields = line.split()
        out.append((fields[1].split("/")[0], fields[2], fields[0]))
    return out


def owner(directory: str) -> str:
    """The file whose corpus_digest routine owns the corpus's published digest.

    The same rule scripts/release-digests.py applies. A record names this file
    as its anchor's routine, so a name that resolves to nothing is a refusal
    here rather than a routine the record claims and nobody can run.
    """
    if directory == "vectors":
        rel = "vectors/gen_manifest.py"
    elif (REPO / directory / "digest.py").is_file():
        rel = directory + "/digest.py"
    else:
        rel = directory + "/gen_vectors.py"
    if not (REPO / rel).is_file():
        raise SystemExit(f"FAIL: {directory} has no digest routine: {rel} is not here")
    return rel


@functools.cache
def corpus_routine(directory: str) -> Any:
    """The corpus digest routine, loaded from the repository's own file by path."""
    path = REPO / owner(directory)
    spec = importlib.util.spec_from_file_location(f"routine_{path.parent.name}", path)
    if spec is None or spec.loader is None:
        raise SystemExit(f"FAIL: {path} could not be loaded")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def corpus_digest_of(directory: str, root: Path, manifest: dict[str, Any]) -> str:
    """The digest the corpus's own routine computes over the files under root."""
    module = corpus_routine(directory)
    if directory == "vectors":
        return str(module.corpus_digest(str(root / directory)))
    return str(module.corpus_digest(manifest, str(root / directory)))


# --------------------------------------------------------------------------
# The admitted population, from the manifest.
# --------------------------------------------------------------------------


def member_id(entry: dict[str, Any]) -> str:
    if isinstance(entry.get("id"), str):
        return str(entry["id"])
    return Path(str(entry["path"])).stem


def paths_in(value: Any) -> list[str]:
    """Every string in a manifest entry that could name a path: a slash, no space."""
    if isinstance(value, str):
        named = "/" in value and "://" not in value and not any(c.isspace() for c in value)
        return [value] if named and len(value) < 256 else []
    if isinstance(value, dict):
        return [p for v in value.values() for p in paths_in(v)]
    if isinstance(value, list):
        return [p for v in value for p in paths_in(v)]
    return []


def member_files(directory: str, entry: dict[str, Any]) -> tuple[list[str], list[dict[str, Any]]]:
    """The files a member's entry names, and the locations they sit in."""
    files: list[str] = []
    locations: list[dict[str, Any]] = []
    for rel in paths_in(entry):
        full = REPO / directory / rel
        parent = str(Path(rel).parent) if "/" in rel else ""
        parent = "" if parent == "." else parent
        if full.is_file():
            files.append(f"{directory}/{rel}")
            locations.append({"dir": parent, "suffix": full.suffix, "recursive": False})
        elif full.is_dir():
            for path in sorted(full.rglob("*")):
                if path.is_file():
                    files.append(path.relative_to(REPO).as_posix())
            locations.append({"dir": parent, "suffix": "", "recursive": True})
    return sorted(set(files)), locations


def population(directory: str, manifest: dict[str, Any]) -> dict[str, Any]:
    members = []
    locations: list[dict[str, Any]] = []
    for entry in manifest["vectors"]:
        files, where = member_files(directory, entry)
        if not files:
            raise SystemExit(f"FAIL: {directory} member {member_id(entry)} names no file")
        members.append({
            "id": member_id(entry),
            "files": [{"path": f, "sha256": sha(read(f))} for f in files],
        })
        locations.extend(where)
    unique = [json.loads(u) for u in sorted({json.dumps(loc, sort_keys=True) for loc in locations})]
    return {"members": members, "locations": [loc for loc in unique if not covered(loc, unique)]}


def covered(loc: dict[str, Any], every: list[dict[str, Any]]) -> bool:
    """A location inside a recursive location that takes every suffix adds nothing."""
    return any(
        other is not loc
        and other["recursive"]
        and other["suffix"] == ""
        and (other["dir"] == "" or loc["dir"] == other["dir"]
             or loc["dir"].startswith(other["dir"] + "/"))
        and (loc["dir"] != other["dir"] or not loc["recursive"] or loc["suffix"] != "")
        for other in every
    )


# --------------------------------------------------------------------------
# The run.
# --------------------------------------------------------------------------


class Run:
    """One process: the argv as recorded, its stdout, stderr and exit code."""

    def __init__(self, shown: str, argv: list[str], env: dict[str, str] | None = None,
                 cwd: Path = REPO) -> None:
        proc = subprocess.run(argv, cwd=cwd, capture_output=True, check=False, env=env)
        self.shown = shown
        self.stdout = proc.stdout
        self.stderr = proc.stderr
        self.code = proc.returncode


def go_runs(binary: str, directory: str) -> tuple[Run, Run, Run]:
    first = Run(f"aee-verify -json {directory}", [binary, "-json", directory])
    second = Run(f"aee-verify -json {directory}", [binary, "-json", directory])
    text = Run(f"aee-verify {directory}", [binary, directory])
    return first, second, text


def scitt_runs() -> tuple[Run, Run, Run]:
    env = dict(os.environ, PYTHONHASHSEED="0")
    script = SCITT + "/check_vectors.py"
    shown = f"PYTHONHASHSEED=0 python {script}"
    first = Run(shown + " --json", [sys.executable, script, "--json"], env)
    second = Run(shown + " --json", [sys.executable, script, "--json"], env)
    text = Run(shown, [sys.executable, script], env)
    return first, second, text


# --------------------------------------------------------------------------
# Consumption (criterion 6 with 2026Oct/0090 and 0091). An artifact is a file
# of the corpus that is neither a member nor the manifest. It is consumed when
# swapping its bytes, with every pin that covers it moved to the new bytes,
# changes the checker's complete native result; opening it is not enough.
# --------------------------------------------------------------------------


def tracked(directory: str) -> list[str]:
    """The files git tracks under a corpus directory, which is what a tag publishes."""
    listed = subprocess.run(["git", "-C", str(REPO), "ls-files", "-z", directory + "/"],
                            capture_output=True, check=True)
    return sorted(p for p in listed.stdout.decode("utf-8").split("\0") if p)


def artifact_paths(directory: str, pop: dict[str, Any]) -> list[str]:
    members = {f["path"] for m in pop["members"] for f in m["files"]}
    manifest = f"{directory}/MANIFEST.json"
    return [p for p in tracked(directory) if p not in members and p != manifest]


def swapped_bytes(rel: str) -> bytes:
    """What the test writes in place of an artifact: fixed, and unlike any real file."""
    return f"replaced by the swap-and-re-pin consumption test: {rel}\n".encode()


class Farm:
    """One corpus copied out, beside links to everything else in the repository.

    The checker runs here with the same relative arguments as in the
    repository, so its output is comparable byte for byte, and a swap touches
    only the copy. release/intake/native/ holds this run's native output, so
    the intake checker can read a record against the farm as its root.
    """

    def __init__(self, directory: str, natives: dict[str, bytes]) -> None:
        self.directory = directory
        self.root = Path(tempfile.mkdtemp(prefix="intake-consumption-"))
        for entry in REPO.iterdir():
            if entry.name not in (directory, "release"):
                (self.root / entry.name).symlink_to(entry)
        shutil.copytree(REPO / directory, self.root / directory, symlinks=True)
        (self.root / "release").mkdir()
        for entry in (REPO / "release").iterdir():
            if entry.name != "intake":
                (self.root / "release" / entry.name).symlink_to(entry)
        for rel, body in natives.items():
            target = self.root / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(body)

    def write(self, rel: str, body: bytes) -> None:
        (self.root / rel).write_bytes(body)

    def restore(self, rels: list[str]) -> None:
        for rel in rels:
            (self.root / rel).write_bytes(read(rel))

    def close(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)


def native_result(run: Run) -> dict[str, Any]:
    return {"sha256": sha(run.stdout), "exit-code": run.code}


def checker_run(directory: str, binary: str, cwd: Path) -> Run:
    if directory == SCITT:
        env = dict(os.environ, PYTHONHASHSEED="0")
        argv = [sys.executable, SCITT + "/check_vectors.py", "--json"]
        return Run("", argv, env, cwd)
    return Run("", [binary, "-json", directory], None, cwd)


def repin(farm: Farm, rel: str, old: bytes, new: bytes) -> tuple[list[str], str]:
    """Move every pin over an artifact's bytes to its new bytes, inside the corpus copy.

    A pin is the artifact's sha256 written in another file of the corpus, and
    the corpus digest when the corpus's own routine covers the artifact. Both
    are moved; the files changed are returned so the swap can be undone.
    """
    directory = farm.directory
    changed: list[str] = []
    for other in tracked(directory):
        if other == rel:
            continue
        body = read(other)
        moved = body.replace(sha(old).encode("ascii"), sha(new).encode("ascii"))
        if moved != body:
            farm.write(other, moved)
            changed.append(other)
    manifest_rel = f"{directory}/MANIFEST.json"
    manifest_body = (farm.root / manifest_rel).read_bytes()
    manifest = json.loads(manifest_body)
    declared = str(manifest.get("corpusDigest", ""))
    try:
        recomputed = corpus_digest_of(directory, farm.root, manifest)
    except Exception as exc:  # noqa: BLE001 -- the routine read the swapped bytes and failed
        return changed, f"not recomputable over the swapped bytes ({type(exc).__name__})"
    if recomputed == declared:
        return changed, "unchanged"
    farm.write(manifest_rel, manifest_body.replace(declared.encode("ascii"),
                                                   recomputed.encode("ascii")))
    if manifest_rel not in changed:
        changed.append(manifest_rel)
    return changed, "recomputed"


def consumption(directory: str, binary: str, farm: Farm, first: Run,
                paths: list[str]) -> list[dict[str, Any]]:
    """The swap-and-re-pin test of 0091, run on every artifact of one corpus."""
    baseline = checker_run(directory, binary, farm.root)
    if (baseline.stdout, baseline.code) != (first.stdout, first.code):
        raise SystemExit(f"FAIL: {directory}: the checker prints other output in the scratch "
                         "copy than in the repository, so a swap there proves nothing")
    out = []
    for rel in paths:
        old, new = read(rel), swapped_bytes(rel)
        farm.write(rel, new)
        changed, digest_state = repin(farm, rel, old, new)
        after = checker_run(directory, binary, farm.root)
        farm.restore([rel] + changed)
        state = "consumed" if native_result(after) != native_result(first) else "unconsumed"
        out.append({
            "path": rel, "sha256": sha(old), "serialization": "bytes", "consumed": state,
            "evidence": {
                "test": "swap-and-re-pin",
                "swapped-in": sha(new),
                "pins-moved": sorted(changed),
                "corpus-digest": digest_state,
                "baseline": native_result(first),
                "swapped": native_result(after),
            },
        })
    return out


def refused_by(document: dict[str, Any], farm: Farm) -> None:
    """For each unconsumed artifact, the grounds that refuse its swap while its pin stays."""
    unconsumed = [a for a in document["artifacts"] if a["consumed"] == "unconsumed"]
    for item in unconsumed:
        item["evidence"]["refused-by"] = [w3cintake.G[2]]
    if w3cintake.rejections(document, str(farm.root)):
        raise SystemExit(f"FAIL: {farm.directory}: the record is refused in the scratch copy "
                         f"before any swap: {w3cintake.rejections(document, str(farm.root))}")
    for item in unconsumed:
        farm.write(item["path"], swapped_bytes(item["path"]))
        found = w3cintake.rejections(document, str(farm.root))
        farm.restore([item["path"]])
        if not found:
            raise SystemExit(f"FAIL: {item['path']} swapped with its pin left in place is "
                             "refused under no ground")
        item["evidence"]["refused-by"] = found


SCITT_LINE = re.compile(r"^OK (\d+) accept, (\d+) reject, (\d+) indeterminate, ")


def aggregate_of(directory: str, text: Run) -> dict[str, Any]:
    output = text.stdout.decode("utf-8")
    if directory == SCITT:
        line = output.rstrip("\n")
        match = SCITT_LINE.match(line)
        if match is None:
            raise SystemExit(f"FAIL: {SCITT} printed no summary line: {output!r}")
        counts = {"accept": int(match[1]), "reject": int(match[2]),
                  "indeterminate": int(match[3])}
        return {"line": line, "total": sum(counts.values()), "counts": counts}
    parsed = w3cintake.parse_summary(output)
    if parsed is None:
        raise SystemExit(f"FAIL: aee-verify {directory} printed no summary: {output!r}")
    line, total, counts = parsed
    return {"line": line, "total": total, "counts": counts}


# --------------------------------------------------------------------------
# The record.
# --------------------------------------------------------------------------


def listing(paths: list[str]) -> str:
    return w3cintake.source_listing(str(REPO), paths) or ""


def checker(directory: str, runs: tuple[Run, Run, Run]) -> dict[str, Any]:
    if directory == SCITT:
        source, deps = SCITT_SOURCE, PYTHON_DEPENDENCIES
        name, runtime = "vectors-scitt-cose/check_vectors.py", {
            "name": "cpython", "version": ".".join(map(str, PYTHON_RUNTIME)),
        }
        build = "uv sync --locked --extra generators"
    else:
        source, deps = GO_SOURCE, GO_DEPENDENCIES
        name, runtime = "aee-verify", {"name": "go", "version": GO_RUNTIME}
        build = "go build -o aee-verify ./cmd/aee-verify"
    return {
        "name": name,
        "revision": {"kind": "source-listing", "paths": source,
                     "serialization": "sha256-listing-v1", "sha256": listing(source)},
        "commands": [build] + [run.shown for run in runs],
        "runtime": runtime,
        "dependencies": [{"path": d, "sha256": sha(read(d)), "serialization": "bytes"}
                         for d in deps],
        "helpers": [],
        "relationship": "same-implementation",
        "shared-verification-code": source,
    }


def non_author_runs(directory: str, digest: str) -> list[dict[str, Any]]:
    if directory not in RELEASE_0176:
        return []
    depth, result = INDEPENDENT_DEPTH.get(directory, STRUCTURE_ONLY)
    return [{
        "operator": "Guigui Wang, Correctover (not an author of this repository)",
        "reader": INDEPENDENT_READER,
        "revision": {"kind": "git-commit", "value": INDEPENDENT_REVISION},
        "relationship": "reference-derived",
        "shared-verification-code": [],
        "basis": "its README: the reference source is read only to derive the rules, and "
                 "no reference code is imported, executed or copied",
        "list-message": "https://lists.w3.org/Archives/Public/public-agent-conformance/"
                        "2026Oct/0041.html",
        "release": "0.17.6",
        "corpus-digest": RELEASE_0176[directory],
        "covers-these-bytes": RELEASE_0176[directory] == digest,
        "depth": depth,
        "result": result,
    }]


def specification_readers(directory: str) -> list[dict[str, Any]]:
    if directory != "vectors-w3c-report":
        return []
    return [{
        "reader": "readers/w3c-report-rs",
        "operator": "an author of this repository",
        "basis": "written from the v0.1 text and the corpus with no code path shared with the "
                 "Go and Python readers (docs/research/w3c-reader-independence.md)",
        "run": "every pull request: scripts/w3c-rails-parity-test.py diffs its output with "
               "the other two readers over the corpus and mutated copies",
    }]


def scope(suite: str, name: str, total: int, covered: bool, signed: bool) -> dict[str, Any]:
    leaves = [
        "whether an implementation written from the specification, run by someone other "
        "than an author, reaches the same verdicts",
    ]
    if not signed:
        leaves.append(f"whether {DIGESTS} is a list a release signed: the signature beside it "
                      "does not verify over these bytes, so the anchor is a located line, "
                      "not a verified one")
    if not covered:
        leaves.append("whether a re-run by someone other than an author on these exact "
                      "bytes agrees; none is on the record for them")
    return {
        "establishes": [f"{name}, at the source listing named here, judges each of the "
                        f"{total} pinned members of {suite} as its manifest declares"],
        "leaves-open": leaves,
        "does-not-claim": list(w3cintake.SCOPE_LIMITS),
    }


def list_is_signed() -> bool:
    """Whether the digest list on disk verifies under the release key beside it.

    A candidate tree carries the previous release's signature over a list that
    has since changed, so its records name an unsigned digest-list line. The
    release commit signs the list, and the records regenerated in that commit
    name a signed digest list, which the intake checker then verifies.
    """
    key = w3cintake.ed25519_public_key(read(PUBLIC_KEY))
    signature = w3cintake.signature_bytes(read(SIGNATURE))
    return key is not None and signature is not None and w3cintake.ed25519_verify(
        key, read(DIGESTS), signature)


def anchor(directory: str, manifest_path: str, digest: str) -> dict[str, Any]:
    routine = owner(directory)
    out: dict[str, Any] = {
        "kind": "digest-list-line",
        "reference": {"uri": f"{REPOSITORY}/blob/main/{DIGESTS}", "path": DIGESTS},
        "manifest": manifest_path,
        "sha256": digest,
        "serialization": "corpus-routine",
        "routine": f"corpus_digest in {routine}",
        "routine-file": routine,
        "verdicts": {"availability-failure": "inconclusive", "integrity-failure": "fail"},
    }
    if list_is_signed():
        out["kind"] = "signed-digest-list"
        out["signature"] = {"path": SIGNATURE, "key": PUBLIC_KEY,
                            "key-sha256": sha(read(PUBLIC_KEY)), "scheme": "ed25519",
                            "serialization": "bytes"}
    return out


def record(
    directory: str, suite: str, digest: str, runs: tuple[Run, Run, Run],
    artifacts: list[dict[str, Any]],
) -> tuple[dict[str, Any], dict[str, bytes]]:
    first, second, text = runs
    for run in runs:
        if run.stderr:
            raise SystemExit(f"FAIL: {run.shown} wrote to stderr: {run.stderr[:200]!r}")
    native = json.loads(first.stdout)
    manifest_path = f"{directory}/MANIFEST.json"
    manifest = json.loads(read(manifest_path))
    if manifest.get("corpusDigest") != digest:
        raise SystemExit(f"FAIL: {manifest_path} declares a digest {DIGESTS} does not list")
    pop = population(directory, manifest)
    ids = [m["id"] for m in pop["members"]]
    native_ids = [m["id"] for m in native["members"]]
    if sorted(native_ids) != sorted(ids):
        raise SystemExit(f"FAIL: {directory}: the checker returned other members than the "
                         "manifest lists")
    stem = directory
    cases_rel, text_rel = f"{NATIVE}/{stem}.json", f"{NATIVE}/{stem}.txt"
    files = {cases_rel: first.stdout, text_rel: text.stdout}
    checks = [
        {"check": m["id"], "state": "fail" if m.get("findings") else "pass",
         "native": {"verdict": m["kind"], "reasons": m.get("findings", [])}}
        for m in native["members"]
    ]
    entries = {member_id(e): e for e in manifest["vectors"]}
    refusals = []
    for check in checks:
        if check["native"]["verdict"] in REFUSAL_VERDICTS or check["state"] == "fail":
            entry = entries[check["check"]]
            fields = {k: entry[k] for k in RULE_FIELDS if k in entry}
            if not fields:
                fields = {"group": str(Path(str(entry.get("path", ""))).parent)}
            rule = "the corpus reader's rule for this member, as its manifest entry states it: " + \
                json.dumps(fields, sort_keys=True, separators=(",", ":"))
            refusals.append({"check": check["check"], "rule": rule,
                             "inputs": [f"member:{check['check']}", f"check:{check['check']}"]})
    member_paths = [(f["path"], f["sha256"]) for m in pop["members"] for f in m["files"]]
    manifest_sha = sha(read(manifest_path))
    is_scitt = directory == SCITT
    name = "vectors-scitt-cose/check_vectors.py" if is_scitt else "aee-verify"
    nonauthor = non_author_runs(directory, digest)
    covered = any(r["covers-these-bytes"] for r in nonauthor)
    observations: list[dict[str, Any]] = [
        {"id": "native-json", "carry": "referenced", "reference": {
            "path": cases_rel, "sha256": sha(first.stdout), "serialization": "bytes"}},
        {"id": "native-text", "carry": "referenced", "reference": {
            "path": text_rel, "sha256": sha(text.stdout), "serialization": "bytes"}},
        {"id": "stderr", "carry": "carried", "carried": ""},
    ]
    stable = sha(first.stdout) == sha(second.stdout)
    result: dict[str, Any] = {
        "format": w3cintake.FORMAT,
        "suite": suite,
        "boundary": {"root": directory, "complete": True, "member-locations": pop["locations"]},
        "manifest": {"closed": True, "path": manifest_path, "sha256": manifest_sha, "ids": ids},
        "members": pop["members"],
        "pin-serialization": "bytes",
        "corpus-digest": {
            "serialization": "sha256-listing-v1",
            "sha256": w3cintake.listing_digest(
                member_paths + [(a["path"], a["sha256"]) for a in artifacts]
                + [(manifest_path, manifest_sha)]),
        },
        "selector": {"language": "id-glob", "expression": "*", "require": "at-least-one",
                     "selected": ids, "matched": len(ids)},
        "checks": checks,
        "aggregate": aggregate_of(directory, text),
        "exit-code": first.code,
        "exit-rule": "zero-iff-every-check-passes",
        "state": "pass" if all(c["state"] == "pass" for c in checks) else "fail",
        "refusal-verdicts": REFUSAL_VERDICTS,
        "refusals": refusals,
        "native": {"format": "corpus-result-json-v1", "cases": "native-json",
                   "summary": None if is_scitt else "native-text",
                   "process-status": {"exit-code": first.code}},
        "observations": observations,
        "artifacts": artifacts,
        "anchor": anchor(directory, manifest_path, digest),
        "checker": checker(directory, runs),
        "specification-readers": specification_readers(directory),
        "non-author-runs": nonauthor,
        "canonicalization": {"encoding": "jcs-sha256"},
        "byte-identity": {"pins": len(member_paths), "serialization": "bytes"},
        "replay-stability": {
            "state": "stable" if stable else "varies",
            "ordering": "emission-order",
            "seed": "PYTHONHASHSEED=0" if is_scitt else None,
            "cause": None,
            "runs": [{"process": "run-1", "sha256": sha(first.stdout)},
                     {"process": "run-2", "sha256": sha(second.stdout)}],
        },
        "exposure": "visible",
        "faults": [],
        "relaxed-controls": [],
        "scope": scope(suite, name, len(ids), covered, list_is_signed()),
    }
    return result, files


def render(document: dict[str, Any]) -> bytes:
    return (json.dumps(document, indent=2, sort_keys=True) + "\n").encode("utf-8")


def build() -> dict[str, bytes]:
    if sys.version_info[:2] != PYTHON_RUNTIME:
        raise SystemExit(f"FAIL: run under CPython {PYTHON_RUNTIME[0]}.{PYTHON_RUNTIME[1]}; "
                         "the SCITT record names that runtime")
    version = subprocess.run(["go", "version"], capture_output=True, text=True, check=True)
    if f"go{GO_RUNTIME}." not in version.stdout:
        raise SystemExit(f"FAIL: run under Go {GO_RUNTIME}; found {version.stdout.strip()}")
    scratch = tempfile.mkdtemp(prefix="intake-records-")
    try:
        binary = os.path.join(scratch, "aee-verify")
        subprocess.run(["go", "build", "-o", binary, "./cmd/aee-verify"], cwd=REPO, check=True)
        out: dict[str, bytes] = {}
        for directory, suite, digest in corpora():
            runs = scitt_runs() if directory == SCITT else go_runs(binary, directory)
            manifest = json.loads(read(f"{directory}/MANIFEST.json"))
            paths = artifact_paths(directory, population(directory, manifest))
            natives = {f"{NATIVE}/{directory}.json": runs[0].stdout,
                       f"{NATIVE}/{directory}.txt": runs[2].stdout}
            farm = Farm(directory, natives)
            try:
                artifacts = consumption(directory, binary, farm, runs[0], paths)
                document, files = record(directory, suite, digest, runs, artifacts)
                refused_by(document, farm)
            finally:
                farm.close()
            out[f"{OUT}/{directory}.intake.json"] = render(document)
            out.update(files)
        return out
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


def on_disk() -> dict[str, bytes]:
    root = REPO / OUT
    if not root.is_dir():
        return {}
    return {p.relative_to(REPO).as_posix(): p.read_bytes() for p in root.rglob("*") if p.is_file()}


def admitted(written: dict[str, bytes]) -> int:
    """Read every record back with the intake checker, the repository as its root.

    It runs on the tree after the native outputs are on disk, because a record's
    claims about bytes are checked against the bytes, not against this script.
    """
    refused = 0
    for rel in sorted(r for r in written if r.endswith(".intake.json")):
        found = w3cintake.evaluate(json.loads(written[rel]), str(REPO))
        if found:
            refused += 1
            print(f"FAIL: the intake checker refuses {rel}: {found}", file=sys.stderr)
    return refused


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    fresh = build()
    if args.check:
        current = on_disk()
        if fresh != current:
            for rel in sorted(set(fresh) | set(current)):
                if fresh.get(rel) != current.get(rel):
                    print(f"FAIL: {rel} is not what a run writes now", file=sys.stderr)
            print("Regenerate with: uv run --locked --extra generators python "
                  "scripts/gen-intake-records.py (a change to the checker's source, a "
                  "corpus or a manifest changes the records)", file=sys.stderr)
            return 1
        if admitted(fresh):
            return 1
        print(f"OK {sum(1 for r in fresh if r.endswith('.intake.json'))} intake records, "
              "each admitted by the intake checker under the repository root")
        return 0
    shutil.rmtree(REPO / OUT, ignore_errors=True)
    for rel, body in fresh.items():
        path = REPO / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(body)
    if admitted(fresh):
        return 1
    print(f"wrote {sum(1 for r in fresh if r.endswith('.intake.json'))} intake records, "
          "each admitted by the intake checker under the repository root")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
