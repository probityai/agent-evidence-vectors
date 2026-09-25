#!/usr/bin/env python3
"""Regenerability gate: every generated file in this repository is the file its
generator produces, checked by producing it.

What went wrong without it
--------------------------
The corpus publishes a determinism recipe. Both vector indexes say the set
regenerates byte-identically from the generator beside it, and the manifest's own
docstring says the same. Nothing ever checked it. Seven vector files and seven
manifest entries were once committed with no builder and no index row behind
them, and the tree stayed green for a day: the harness replayed all of them and
passed, because the harness reads the committed bytes and the manifest, and both
of those had been written by hand. The defect surfaced only when someone ran the
manifest generator, whose closure check refused. A published recipe that nobody
executes is a claim, and this repository has spent its history removing those.

Three separate things were wrong in that one commit and only the third was
visible to any existing check: five of the files carried a different constant set
from the generator they were filed beside, three of them carried a record whose
signature does not verify, and the manifest had been rewritten in a different
order from the one its generator emits. All three are the same defect --
committed bytes that no generator produces -- and this gate is the shape of check
that catches all three at once, because it does not inspect the bytes at all. It
regenerates them and compares.

How it works
------------
The tracked tree is copied into a temporary directory, the generators are run
there in dependency order, and every file they own is compared with the committed
one. Nothing in the repository is written. The copy is what makes the comparison
honest: running the generators in place would overwrite the very bytes the gate
is supposed to be comparing against, so a run would always agree with itself.

What "own" means is declared rather than inferred, in OWNED below, and a file
matching one of those patterns in the committed tree and missing from the
regenerated one fails just as loudly as one whose bytes differ. That direction is
the one that caught nothing before: a vector file with no builder is not a
mismatch, it is an absence, and an absence is what a checksum comparison over the
files that were produced will never see.

Two generated artifacts are deliberately NOT listed here.
``packaging/conformance-report.json`` is a run artifact
rather than a source, and the run that writes it is its own check.

Usage:
    python3 scripts/regenerability-gate.py
    python3 scripts/regenerability-gate.py --root <tree>   (for its own tests)
Exit 0 when every generated file regenerates byte-identically; 1 otherwise.
"""

from __future__ import annotations

import argparse
import filecmp
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

# The generators, in dependency order: the manifest is derived from the indexes,
# and the reject index is written by the reject generator, so the manifest runs
# last or it derives from an index one revision behind.
GENERATORS = (
    "vectors/accept/gen_valid_vectors.py",
    "vectors/reject/gen_invalid_vectors.py",
    "vectors/gen_manifest.py",
    # The AI Agent Action suite. It builds its own manifest in the same run, so
    # it has no ordering relationship with the three above and is listed last.
    # It arrived as a corpus that published a regeneration recipe -- its
    # generator's own docstring says "Regenerate byte-identically" -- while no
    # gate ran it, which is the precise claim-nobody-executes this file was
    # written about. It passed only because somebody ran it by hand.
    "vectors-ai-agent-action/gen_vectors.py",
    # The artifact-binding corpus. Its members are whole trial DIRECTORIES
    # rather than single statements, which is a larger surface to hand-place
    # and therefore a larger reason to derive it.
    "vectors-artifact-binding/gen_vectors.py",
    # The SCITT/COSE carriage suite. Like the one above it builds its own
    # manifest and its own index in the same run, so it has no ordering
    # relationship with anything else and is listed last.
    "vectors-scitt-cose/gen_vectors.py",
    # The ACI suite. A member is a whole DEPLOYMENT serialised into one file, so
    # every identifier and the corpus digest are functions of bytes no person
    # can write into a table by hand.
    "vectors-aci/gen_vectors.py",
    # The W3C per-check report corpus. Every member is a whole report whose
    # check-set digest and identifier are functions of its bytes, and the
    # generator refuses a member the validator does not answer as claimed.
    "vectors-w3c-report/gen_vectors.py",
    # The Observed Effect suite. It builds its own manifest and its own index in
    # the same run, so it has no ordering relationship with anything above. It is
    # listed because it arrived publishing a regeneration recipe -- its
    # generator's docstring says "Regenerate byte-identically" -- with no gate
    # running it, which is the same state this file's header records for the
    # AI Agent Action suite.
    "vectors-observed-effect/gen_vectors.py",
    # The conformance appendix for the W3C report format is rendered from that
    # corpus's manifest: every identifier in it is a function of the vectors'
    # bytes, so it runs after the corpus generator and is owned like a vector.
    # The MCP response-phase corpus. It builds its manifest and index in the
    # same run, so it has no ordering relationship with anything above; every
    # member identifier and the corpus digest are functions of the operation
    # bytes, which is the reason it is derived rather than hand-placed.
    "vectors-mcp-response-phase/gen_vectors.py",
    # The AI generation predicate corpus. It signs with fixed test keys, so its
    # members, sidecars, manifest and index are all functions of the generator
    # and the vendored text; nothing in it is placed by hand.
    "vectors-ai-generation/gen_vectors.py",
    "scripts/gen-w3c-appendix.py",
)

# Every file a generator above is responsible for, as a directory and a glob.
# Declared rather than discovered: a gate that compared whatever the generators
# happened to write could not tell a file that was not regenerated from a file
# that was never meant to be.
OWNED = (
    # One flat directory of content-addressed statements, so the pattern is the
    # identifier shape rather than a prefix that named the verdict.
    ("vectors/statements", "v*.json"),
    # The vate-* prefix is listed beside each id prefix it joins rather than
    # folded into it, because a pattern that enumerates ids by prefix skips a
    # family it was not told about and then reports the corpus clean -- which is
    # the shape of failure this gate exists to catch. Eight vector files sat
    # outside this tuple while the gate printed a total that agreed with itself.
    ("vectors/reject", "INDEX.md"),
    # Emitted since the accept identifiers became a function of the bytes:
    # a content digest is not something a person can write into a table.
    ("vectors/accept", "INDEX.md"),
    # The indeterminate family is built by the reject generator, from the same
    # parents, the same derived keys and the same second-fault self-check; only
    # the claim its manifest entry makes differs. It is listed here and not
    # under its own generator for that reason, and it is listed at all because a
    # bucket outside this gate is a bucket whose files can be hand-placed, which
    # is the defect the gate was written for.
    ("vectors/indeterminate", "INDEX.md"),
    ("vectors", "MANIFEST.json"),
    # The AI Agent Action suite. The record sidecars are listed because the
    # chain-hash members are preimages rather than Statements: a sidecar that
    # stopped being regenerated would leave the vector claiming a divergence
    # over bytes no generator writes.
    # Named after their own bytes and no longer sorted into a directory per
    # verdict, so the pattern is the identifier shape rather than a prefix that
    # said which answer the file carried.
    ("vectors-ai-agent-action/statements", "v*.json"),
    ("vectors-ai-agent-action/records", "*.jsonl"),
    ("vectors-ai-agent-action", "MANIFEST.json"),
    # The artifact-binding corpus. INDEX.md is emitted here rather than authored
    # by hand, unlike its siblings, because every row restates an identifier
    # that is a function of the bytes it names.
    ("vectors-artifact-binding", "MANIFEST.json"),
    ("vectors-artifact-binding", "INDEX.md"),
    ("vectors-artifact-binding", "public.key"),
    # The SCITT/COSE carriage suite. Its INDEX.md is OWNED here, unlike the
    # hand-authored indexes above, because that file is emitted from the
    # manifest: an index a person maintains beside a corpus drifts from it and
    # both halves keep looking authoritative, which this repository has already
    # paid for once.
    ("vectors-scitt-cose/statements", "v*.json"),
    ("vectors-scitt-cose", "MANIFEST.json"),
    ("vectors-scitt-cose", "INDEX.md"),
    ("vectors-aci/deployment-members", "v*.json"),
    ("vectors-aci", "MANIFEST.json"),
    # The Observed Effect suite. Its INDEX.md is emitted from the manifest for
    # the reason the SCITT/COSE entry above gives, and its members are named
    # after their own bytes: the corpus digest and all 31 identifiers move
    # together whenever any member does, which is how this corpus's README came
    # to publish a digest no member set produces.
    ("vectors-observed-effect/statements", "v*.json"),
    ("vectors-observed-effect", "MANIFEST.json"),
    ("vectors-observed-effect", "INDEX.md"),
    ("vectors-w3c-report/vectors", "v*.json"),
    ("vectors-w3c-report", "MANIFEST.json"),
    ("vectors-w3c-report", "INDEX.md"),
    ("vectors-w3c-report", "MUTATION-SWEEP.md"),
    ("docs", "W3C-V01-CONFORMANCE-APPENDIX.md"),
    # The MCP response-phase corpus. Its INDEX.md is emitted from the manifest,
    # and its members are named after their own bytes, so the digest and every
    # identifier move together whenever any member does.
    ("vectors-mcp-response-phase/vectors", "v*.json"),
    ("vectors-mcp-response-phase", "MANIFEST.json"),
    ("vectors-mcp-response-phase", "INDEX.md"),
    # The AI generation predicate corpus: the members, the artifact and trailer
    # sidecars they are checked against, and the manifest and index built from
    # them. A sidecar no generator writes would let a member's digest name bytes
    # nobody can reproduce.
    ("vectors-ai-generation/statements", "v*.json"),
    ("vectors-ai-generation/artifacts", "*.txt"),
    ("vectors-ai-generation/trailers", "*.txt"),
    ("vectors-ai-generation", "MANIFEST.json"),
    ("vectors-ai-generation", "INDEX.md"),
)

# Deliberately NOT owned above, for the two reasons the header already gives.
# ``vectors-ai-agent-action/{accept,reject}/INDEX.md`` are authored by hand, as
# ``vectors/accept/INDEX.md`` is. ``vectors-ai-agent-action/attacks/artifacts/``
# is the output of a run rather than a source: run_attacks.py shells out to a
# node process to demonstrate that ECMAScript orders object members differently,
# so listing it here would make this gate refuse on any machine without node --
# a gate that fails for a reason unrelated to the property it checks.

REMEDY = (
    "A committed file that its generator does not reproduce cannot be "
    "regenerated by anyone, and the determinism recipe both vector indexes "
    "publish is false for it. Fix the generator so it emits the committed bytes, "
    "or -- if the committed bytes are the wrong ones -- regenerate them, say so, "
    "and re-vendor the consumer copies with "
    "scripts/consumer-lag-gate.py --sync. Never edit a generated file by hand: "
    "the next run of its generator silently reverts it."
)


def tracked(root: Path) -> list[str]:
    listed = subprocess.run(
        ["git", "-C", str(root), "ls-files"],
        capture_output=True,
        text=True,
        check=True,
    )
    return listed.stdout.split()


def stage(root: Path, destination: Path) -> None:
    """Copy the tracked tree, so the generators write over a copy and not a source."""
    for rel in tracked(root):
        origin = root / rel
        if not origin.is_file():
            continue
        target = destination / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(origin, target)


def wipe(destination: Path) -> None:
    """Delete every owned file from the copy before the generators run.

    Without this the gate has a blind spot in the exact shape of the defect it
    exists to catch. The copy starts as the committed tree, so a file the
    generators never touch is still sitting there when the comparison runs, and
    it compares equal to itself: a vector with no builder passes, silently,
    because nothing distinguishes 'regenerated identically' from 'never written'.
    Emptying the owned set first makes absence visible as absence.
    """
    for rel, path in owned_files(destination).items():
        del rel
        path.unlink()


def regenerate(destination: Path) -> list[str]:
    failures: list[str] = []
    for rel in GENERATORS:
        proc = subprocess.run(
            [sys.executable, str(destination / rel)],
            cwd=str(destination),
            capture_output=True,
            text=True,
            check=False,
        )
        if proc.returncode != 0:
            failures.append(
                f"{rel}: exited {proc.returncode} rather than regenerating its "
                f"files.\n{(proc.stdout + proc.stderr).strip()}"
            )
    return failures


def owned_files(root: Path) -> dict[str, Path]:
    found: dict[str, Path] = {}
    for directory, pattern in OWNED:
        for path in sorted((root / directory).glob(pattern)):
            found[f"{directory}/{path.name}"] = path
    return found


def compare(root: Path, destination: Path) -> list[str]:
    committed = owned_files(root)
    regenerated = owned_files(destination)
    failures: list[str] = []
    for rel in sorted(set(committed) - set(regenerated)):
        failures.append(
            f"{rel} is committed and no generator produced it. A file no generator "
            "writes is a file nobody can reproduce, and it is how five vectors "
            "entered this corpus."
        )
    for rel in sorted(set(regenerated) - set(committed)):
        failures.append(
            f"{rel} is produced by a generator and is not committed, so the "
            "corpus a reader clones is smaller than the one the generators build."
        )
    for rel in sorted(set(committed) & set(regenerated)):
        if not filecmp.cmp(committed[rel], regenerated[rel], shallow=False):
            failures.append(f"{rel} differs from what its generator produces.")
    return failures


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        description="every generated file is the file its generator produces"
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=REPO_ROOT,
        help="the tree to check; a staged copy when this gate's own tests run it",
    )
    root = parser.parse_args(argv[1:]).root.resolve()

    with tempfile.TemporaryDirectory() as raw:
        destination = Path(raw) / "regenerated"
        destination.mkdir()
        stage(root, destination)
        wipe(destination)
        failures = regenerate(destination)
        failures.extend(compare(root, destination))
        checked = len(owned_files(root))

    if failures:
        print(
            f"FAIL: {len(failures)} generated file(s) or generator(s) do not hold:",
            file=sys.stderr,
        )
        for failure in failures:
            print(f"  {failure}", file=sys.stderr)
        print(f"\n{REMEDY}", file=sys.stderr)
        return 1
    print(
        f"OK: all {checked} generated file(s) regenerate byte-identically from "
        f"the {len(GENERATORS)} generators that own them."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
