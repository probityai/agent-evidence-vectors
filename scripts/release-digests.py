#!/usr/bin/env python3
"""Write the one file a release signature covers: the digest of every corpus.

Why one file. A repository that ships more than one corpus can sign each of
them, and then a consumer who verifies one of them has verified one of them.
The thing a stranger actually needs to establish is WHICH BYTES THEY RAN, and
that is a statement about the whole set plus the mapping between the corpora --
which digest belongs to which manifest, at which revision. So the signed object
is a single list, and one signature covers the set and the mapping together.
Splitting it would let a swap of one corpus for another corpus's signature go
unremarked.

Why nothing here is typed. Every digest is RECOMPUTED from the vector files on
disk with that corpus's own published routine, and then checked against what
the manifest declares. A generator that copied the declared value would sign
whatever a manifest happened to say, so a signature would certify a number
nobody had recomputed -- the exact shape of an attestation that asserts rather
than establishes, which is what this repository exists to refuse.

Why the corpora are enumerated from git rather than from a walk. `git ls-files`
is the tree a tag publishes. A corpus that is on disk and untracked is not in
the release, and a corpus that is tracked and missing from disk is a failure
rather than a shorter list.

Why an unregistered corpus is a refusal. Each corpus computes its digest with
its own preimage (the AEE corpus hashes `<rel>\\0<sha256hex>\\n` lines, the AI
Agent Action corpus hashes concatenated file bytes in identifier order), so
there is no single routine to fall back on. A third corpus that arrives without
an entry in RECOMPUTERS makes this exit non-zero and say so, rather than
publishing a digest nothing recomputed. A default branch here would be the
silent-pass defect in one line.

Usage:
  uv run python scripts/release-digests.py            # write release/CORPUS-DIGESTS.txt
  uv run python scripts/release-digests.py --check    # refuse a file that is not
                                                      # what would be written
  uv run python scripts/release-digests.py --root <tree>

Exit 0 when the file is written (or, under `--check`, already correct); 1 when a
corpus disagrees with its own files, when a tracked corpus is unregistered, or
when `--check` finds any difference.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
OUTPUT_REL = "release/CORPUS-DIGESTS.txt"
CHANGES_NAME = "CHANGES.md"

# The header is prose about the format, never a figure. Anything countable in
# this file is derived below.
HEADER = (
    "# One line per corpus: <sha256 corpus digest>  <manifest path>  <suite>  "
    "vectors=<n>  <suiteRevision=<n>|no-suiteRevision>\n"
    "# Regenerate: python3 scripts/release-digests.py    Check: --check\n"
    "# Every digest is recomputed from the vector files on disk, never copied "
    "from the manifest.\n"
)

# `no-suiteRevision` is written out rather than left blank. A corpus with no
# revision ledger and a corpus whose revision failed to parse must not serialize
# to the same bytes as each other or as a missing column.
NO_REVISION = "no-suiteRevision"


class CorpusError(Exception):
    """A corpus does not agree with its own files, or cannot be recomputed."""


def _load(path: Path) -> Any:
    """Load a corpus's own module by PATH, not by import name.

    The two generators live inside the corpus directories rather than on any
    import path, and the whole point of calling them is that each corpus owns
    its own preimage. Loading by path keeps that ownership and keeps this file
    from acquiring a second copy of either routine.
    """
    spec = importlib.util.spec_from_file_location(path.stem, path)
    if spec is None or spec.loader is None:
        raise CorpusError(f"{path} could not be loaded, so its digest cannot be recomputed")
    module = importlib.util.module_from_spec(spec)
    sys.modules.setdefault(spec.name, module)
    spec.loader.exec_module(module)
    return module


def _owner(root: Path) -> Path:
    """The module that owns this corpus's preimage.

    digest.py when the corpus ships one, gen_vectors.py otherwise. A corpus
    whose generator needs third-party libraries would otherwise put them on this
    path, and this path has to run for somebody who installed nothing: v0.10.0
    shipped with the SCITT preimage inside a generator that imports cbor2 and
    pycose at module scope, and the first command the README tells a reader to
    run failed in a fresh clone with ModuleNotFoundError. Generation may depend
    on whatever it needs. Verification may not.
    """
    shipped = root / "digest.py"
    return shipped if shipped.exists() else root / "gen_vectors.py"


def _recompute_aee(root: Path, manifest: dict[str, Any]) -> str:
    """The AEE corpus digest, from the generator that publishes it."""
    del manifest
    module = _load(root / "gen_manifest.py")
    return str(module.corpus_digest(str(root)))


def _recompute_agent_action(root: Path, manifest: dict[str, Any]) -> str:
    """The AI Agent Action corpus digest, from the generator that publishes it.

    It used to come from that corpus's check_vectors.py, which was deleted with
    the four other per-corpus runners once the Go harness covered what they
    checked. The digest was never the runner's to own: the generator writes the
    bytes, so the generator answers for them, which is also where the AEE corpus
    above is read from.
    """
    module = _load(_owner(root))
    return str(module.corpus_digest(manifest, str(root)))


#: Corpus directory -> the routine that OWNS that corpus's preimage. Imported,
#: never restated: a second spelling of a preimage is a digest that drifts.
def _recompute_from_generator(root: Path, manifest: dict[str, Any]) -> str:
    """Every other corpus, through the corpus_digest its generator exports.

    One routine rather than one per corpus, because after the five per-corpus
    runners were deleted each generator gained the same entry point and the
    difference between the corpora lives inside it: identifier order for some,
    manifest order for others, canonical entries for the one whose members are
    whole directories. A wrapper per corpus here would be five more places to
    get a preimage wrong and nothing to gain.
    """
    module = _load(_owner(root))
    return str(module.corpus_digest(manifest, str(root)))


RECOMPUTERS: dict[str, Callable[[Path, dict[str, Any]], str]] = {
    "vectors": _recompute_aee,
    "vectors-ai-agent-action": _recompute_agent_action,
    "vectors-aci": _recompute_from_generator,
    "vectors-acs-core": _recompute_from_generator,
    "vectors-anchor-stream": _recompute_from_generator,
    "vectors-artifact-binding": _recompute_from_generator,
    "vectors-mcp-record-contract": _recompute_from_generator,
    "vectors-mcp-response-phase": _recompute_from_generator,
    "vectors-observed-effect": _recompute_from_generator,
    "vectors-receipt-signature": _recompute_from_generator,
    "vectors-scitt-cose": _recompute_from_generator,
    "vectors-w3c-report": _recompute_from_generator,
}


def tracked_manifests(root: Path) -> list[str]:
    """Every tracked `<dir>/MANIFEST.json`, in path order."""
    listed = subprocess.run(
        ["git", "-C", str(root), "ls-files", "*/MANIFEST.json"],
        capture_output=True,
        text=True,
        check=True,
    )
    return sorted(
        rel
        for rel in listed.stdout.split()
        if rel.count("/") == 1 and rel.endswith("/MANIFEST.json")
    )


def suite_revision(directory: Path) -> str:
    """The revision this corpus is at, from its own changelog, or the absence."""
    changes = directory / CHANGES_NAME
    if not changes.is_file():
        return NO_REVISION
    for line in changes.read_text(encoding="utf-8").splitlines():
        if line.startswith("## suiteRevision "):
            token = line.removeprefix("## suiteRevision ").split()[0]
            if token.isdigit():
                return f"suiteRevision={token}"
            break
    return NO_REVISION


def line_for(root: Path, rel: str) -> str:
    """One corpus, recomputed and checked against what it declares."""
    directory = root / Path(rel).parent
    name = directory.name
    if name not in RECOMPUTERS:
        raise CorpusError(
            f"{rel} is tracked and {name!r} has no entry in RECOMPUTERS, so nothing "
            "here can recompute its digest. Register the routine that owns that "
            "corpus's preimage; a signature over a digest nobody recomputed "
            "certifies a number somebody typed."
        )
    path = root / rel
    if not path.is_file():
        raise CorpusError(f"{rel} is tracked and absent from the tree")
    manifest = json.loads(path.read_text(encoding="utf-8"))
    declared = str(manifest.get("corpusDigest", ""))
    recomputed = RECOMPUTERS[name](directory, manifest)
    if declared != recomputed:
        raise CorpusError(
            f"{rel} declares corpusDigest {declared or 'nothing'} and the files on "
            f"disk hash to {recomputed}. Regenerate the corpus before signing it."
        )
    suite = str(manifest.get("suite") or "")
    if not suite:
        raise CorpusError(f"{rel} names no suite, so its line would not say what it is")
    count = len(manifest["vectors"])
    return f"{recomputed}  {rel}  {suite}  vectors={count}  {suite_revision(directory)}"


def render(root: Path) -> str:
    """The whole file, exactly as it would be written."""
    manifests = tracked_manifests(root)
    if not manifests:
        raise CorpusError(
            "no tracked */MANIFEST.json was found, so this would sign an empty list. "
            "An empty subject set passes every check while covering nothing."
        )
    return HEADER + "".join(f"{line_for(root, rel)}\n" for rel in manifests)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=REPO_ROOT, help="the tree to read")
    parser.add_argument(
        "--check",
        action="store_true",
        help="refuse rather than write when the file on disk differs",
    )
    args = parser.parse_args()
    root = args.root.resolve()
    output = root / OUTPUT_REL

    try:
        rendered = render(root)
    except CorpusError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1

    if args.check:
        if not output.is_file():
            print(
                f"FAIL: {OUTPUT_REL} does not exist, so there is nothing for a "
                "signature to cover.",
                file=sys.stderr,
            )
            return 1
        on_disk = output.read_text(encoding="utf-8")
        if on_disk != rendered:
            print(
                f"FAIL: {OUTPUT_REL} is not what the corpora on disk produce. "
                "Regenerate it and re-sign; a signature over the old bytes says "
                "nothing about these ones.",
                file=sys.stderr,
            )
            for tag, text in (("on disk", on_disk), ("recomputed", rendered)):
                for line in text.splitlines():
                    if line.startswith("#"):
                        continue
                    print(f"  {tag}: {line}", file=sys.stderr)
            return 1
        print(
            f"OK: {OUTPUT_REL} is exactly what the corpora on disk produce, and "
            "every digest in it was recomputed rather than read."
        )
        return 0

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(rendered, encoding="utf-8")
    print(f"wrote {OUTPUT_REL}")
    for line in rendered.splitlines():
        if not line.startswith("#"):
            print(f"  {line}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
