"""The evidence this corpus reuses by digest, and the check that the digests still hold.

Each finding in a case points at one member of a sibling corpus: the sibling, the member, the
file, the SHA-256 of that file, and the suite's own answer for it. ``reuse.json`` records
those pointers, so this corpus regenerates without the siblings and never copies their
bytes. ``check`` compares every pointer with the sibling member when the sibling is present,
and says plainly how many were verified and how many siblings are not in the tree yet.

A pointer whose sibling is absent is PENDING, never verified: a corpus that cites a pending
sibling is correct only once that sibling lands with the same digest, which is what
``--require-all`` checks.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
CORPORA = HERE.parent
REUSE = HERE / "reuse.json"
#: Each suite's affirmative decision words, folded to ``accept``; every other word is
#: ``reject``. The fold is the one place a suite's vocabulary meets this contract's.
AFFIRMATIVE = frozenset({"verified", "allow", "supported", "accepted", "accept"})
#: (corpus directory, member, file in the member that holds the evidence)
POINTERS = (
    ("vectors-principal-binding", "uma-bound", "binding.jws"),
    ("vectors-principal-binding", "uma-signed-by-other-key", "binding.jws"),
    ("vectors-identity-binding", "web-verified", "envelope.json"),
    ("vectors-actor-marker-survival", "accept-two-hop", "record.json"),
    ("vectors-actor-marker-survival", "own-marker-stripped", "record.json"),
    ("vectors-holder-bound-credential", "accept-single-presentation", "record.json"),
    ("vectors-holder-bound-credential", "credential-is-bearer", "record.json"),
    ("vectors-holder-bound-credential", "proof-signed-by-other-key", "record.json"),
    ("vectors-delegator-right", "allow-entitled-delegator", "record.json"),
    ("vectors-delegator-right", "delegate-scope-exceeds-delegator", "record.json"),
    ("vectors-credential-reachability", "contained", "envelope.json"),
    ("vectors-credential-reachability", "exposed", "envelope.json"),
    ("vectors-credential-reachability", "signed-by-agent-key", "envelope.json"),
    ("vectors-grade-floor", "e1-observed", "case.json"),
    ("vectors-grade-floor", "e2-enforced", "case.json"),
    ("vectors-grade-floor", "e4-anchored", "case.json"),
    ("vectors-grade-floor", "e0-self-stamped-e4", "case.json"),
)


def _manifest(corpus_dir: Path) -> dict[str, Any]:
    loaded: dict[str, Any] = json.loads((corpus_dir / "MANIFEST.json").read_text(encoding="utf-8"))
    return loaded


def entry_for(corpus: str, member: str, filename: str, corpus_dir: Path) -> dict[str, Any]:
    """The reuse record of one member, read from its sibling corpus."""
    manifest = _manifest(corpus_dir)
    row = next(v for v in manifest["vectors"] if v["id"] == member)
    expected = row["expected"]
    out: dict[str, Any] = {
        "corpus": corpus,
        "decision": "accept" if expected["decision"] in AFFIRMATIVE else "reject",
        "file": filename,
        "member": member,
        "reason": expected["reason"],
        "sha256": row["files"][filename],
        "suite": manifest["suite"],
    }
    if "derivedGrade" in expected:
        out["rung"] = expected["derivedGrade"]
    return out


def refresh(sources: dict[str, Path]) -> dict[str, Any]:
    """Rebuild reuse.json from the sibling corpora; ``sources`` overrides a corpus path."""
    entries = {}
    for corpus, member, filename in POINTERS:
        directory = sources.get(corpus, CORPORA / corpus)
        entries[f"{corpus}/{member}"] = entry_for(corpus, member, filename, directory)
    return {"entries": entries}


def load() -> dict[str, dict[str, Any]]:
    """The committed pointers."""
    loaded: dict[str, dict[str, Any]] = json.loads(REUSE.read_text(encoding="utf-8"))["entries"]
    return loaded


def check(root: Path = CORPORA, require_all: bool = False) -> tuple[int, int, list[str]]:
    """(verified, pending, errors): pointers matched against the siblings found under root."""
    verified, pending, errors = 0, 0, []
    for key, entry in sorted(load().items()):
        corpus_dir = root / entry["corpus"]
        if not (corpus_dir / "MANIFEST.json").exists():
            pending += 1
            continue
        try:
            fresh = entry_for(entry["corpus"], entry["member"], entry["file"], corpus_dir)
        except (StopIteration, KeyError, OSError, ValueError) as exc:
            errors.append(f"{key}: sibling member unreadable: {exc}")
            continue
        if fresh != entry:
            errors.append(f"{key}: the sibling no longer matches the pointer")
            continue
        path = corpus_dir / "cases" / entry["member"] / entry["file"]
        if hashlib.sha256(path.read_bytes()).hexdigest() != entry["sha256"]:
            errors.append(f"{key}: the file on disk differs from the manifest digest")
            continue
        verified += 1
    if require_all and pending:
        errors.append(f"{pending} pointer(s) have no sibling corpus in the tree")
    return verified, pending, errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument("--root", default=str(CORPORA), help="directory holding the corpora")
    parser.add_argument("--require-all", action="store_true", help="refuse a pending sibling")
    parser.add_argument(
        "--refresh",
        nargs="*",
        metavar="CORPUS=DIR",
        help="rewrite reuse.json from the siblings (DIR overrides a corpus path)",
    )
    args = parser.parse_args(argv)
    if args.refresh is not None:
        overrides = {k: Path(v) for k, _, v in (a.partition("=") for a in args.refresh)}
        REUSE.write_text(
            json.dumps(refresh(overrides), indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        print(f"wrote {REUSE.name} with {len(POINTERS)} pointers")
        return 0
    verified, pending, errors = check(Path(args.root), args.require_all)
    for error in errors:
        print(error)
    total = len(load())
    print(
        f"reuse: {verified} of {total} pointers verified, {pending} pending, {len(errors)} errors"
    )
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
