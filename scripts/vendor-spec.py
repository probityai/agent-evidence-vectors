#!/usr/bin/env python3
"""Re-vendor the predicate specification from an upstream checkout.

The vendored copy at ``spec/predicates/adversarial-execution-evidence.md`` is a
byte-verbatim copy of the specification the standards body reviews, and the
whole point of vendoring it is that a relying party can implement from this
repository alone and get the same answers. That guarantee only holds if the
copy is honestly labelled with where it came from.

It was not. The commit the copy tracked lived as a sentence in
``spec/README.md``, typed by hand at vendor time, and it went stale the first
time the upstream branch moved: the README claimed ``4a36b19`` while the
vendored bytes were those of ``83da03e``, three normative revisions later.
That is not a cosmetic error. An independent implementer fetched exactly that
commit from the URL the README implies in order to diff the vendored copy
against branch head and certify no version skew -- so a stale pin either
manufactures a drift report that does not exist or hides one that does, and
either way it corrupts the only external evidence we have that the
specification is unambiguous.

So the pin is derived, never typed. This script resolves the commit with git,
copies the bytes, and writes ``spec/VENDOR-PIN.json``; the drift gate then
checks the vendored bytes against that record on every run, and the README
states no constant of its own.

The pin also has to say WHERE, and for a while it did not. It named
``in-toto/attestation``, which is where the pull request is reviewed and not
where the commit can be fetched: the PR is opened from a fork branch, and a
plain clone of the review venue resolves neither the commit nor its bytes. One
field was answering two questions and only the first answer was true. So the
record now carries ``commitRepo``, ``ref`` and ``refKind`` alongside the review
venue, all three derived from the checkout's own remotes, and this script
refuses to write a pin whose commit is not reachable from the ref it names.

``refKind`` is the honest part. A branch head moves, so a pin naming one is
currently-true rather than permanent; a tag does not. See the vendored-revision
tag row in ``TODO.md`` for the flip.

Usage:
    python3 scripts/vendor-spec.py --from ~/path/to/attestation [--ref HEAD]
    python3 scripts/vendor-spec.py --from ... --ref <tag> --remote <remote>
    python3 scripts/vendor-spec.py --from ... --ref <branch> --at <commit>

Re-vendoring is a normative change. Regenerate the corpus and bump
``suiteRevision`` in vectors/CHANGES.md afterwards; the drift gate fails until
vectors/gen_manifest.py has re-pinned the digest.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from difflib import SequenceMatcher
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SPEC_REL = "spec/predicates/adversarial-execution-evidence.md"
PIN_PATH = REPO_ROOT / "spec" / "VENDOR-PIN.json"

# The upstream pull request this predicate is proposed in. The commit is
# resolved from the checkout; only the PR identity is a constant, and it is a
# constant because a new PR number is a new vendoring relationship, not a drift.
#
# THIS NAMES THE REVIEW VENUE AND NOT THE OBJECT STORE, and the difference is
# the whole reason ``commitRepo`` exists below. ``vectors/gen_manifest.py``
# builds the citation ``in-toto/attestation#570`` out of these two constants,
# which is correct: that is where the pull request is read and reviewed. It is
# not where the pinned commit can be fetched. The commit lives on the branch
# the pull request is opened FROM, in a fork, and a plain clone of the review
# venue does not carry it -- ``git clone https://github.com/in-toto/attestation
# && git cat-file -t <pin>`` exits 128. One field was answering both questions
# and only the first answer was true, so a reproducer following the pin landed
# on a repository the commit is not in.
UPSTREAM_REPO = "in-toto/attestation"
UPSTREAM_PR = 570


# The gates that hold a content pin for one citation spelling. Each keeps its
# own ledger, so one refusing does not leave the other half-written.
#
# The `spec:NNN` line-number spelling was retired by the anchor migration, and
# its gate went with it: `scripts/spec-drift-gate.py` now holds every
# `spec:<anchor-id>@<digest>` citation to the prose it names, and it needs no
# resync because an anchor citation carries its own digest inline.
SYNCED_GATES = ("scripts/spec-anchor-gate.py",)


def resync(gate: str) -> bool:
    """Rewrite one pin ledger, and report whether it agreed to."""
    done = subprocess.run(
        [sys.executable, str(REPO_ROOT / gate), "--sync"], check=False
    )
    return done.returncode == 0


def git(checkout: Path, *args: str) -> str:
    """Run git in checkout and return stripped stdout, or exit with its error."""
    proc = subprocess.run(
        ["git", "-C", str(checkout), *args],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        raise SystemExit(
            f"FAIL: git {' '.join(args)} in {checkout}: {proc.stderr.strip()}"
        )
    return proc.stdout.strip()


def owner_repo(url: str) -> str:
    """`owner/name` from a GitHub remote URL, in either spelling."""
    trimmed = url.strip().removesuffix(".git")
    if trimmed.startswith("git@"):
        trimmed = trimmed.partition(":")[2]
    else:
        trimmed = re.sub(r"^[a-z+]+://", "", trimmed).partition("/")[2]
    parts = [p for p in trimmed.split("/") if p]
    if len(parts) < 2:
        raise SystemExit(f"FAIL: cannot read owner/name out of remote URL {url!r}")
    return "/".join(parts[-2:])


def locate(checkout: Path, ref: str, commit: str, remote_hint: str | None
           ) -> tuple[str, str, str]:
    """Where the pinned commit can actually be fetched from.

    Returns `(commitRepo, ref, refKind)`. Every part is read out of the
    checkout; nothing here is typed, for the same reason the commit is not.

    A branch is resolved through its tracking ref, so the answer is the remote
    git itself would fetch from. A tag has no tracking ref and needs
    ``--remote``. Anything else REFUSES: a pin naming the wrong repository is
    exactly the failure this function was added to stop, and guessing a remote
    would reintroduce it with the guess hidden one level down.
    """
    proc = subprocess.run(
        ["git", "-C", str(checkout), "rev-parse", "--verify", "--quiet",
         f"refs/tags/{ref}"],
        capture_output=True, text=True, check=False,
    )
    if proc.returncode == 0:
        if not remote_hint:
            raise SystemExit(
                f"FAIL: {ref} is a tag, which carries no tracking ref, so the "
                "repository publishing it cannot be derived. Re-run with "
                "--remote naming the remote it was fetched from."
            )
        verify_ref = f"refs/tags/{ref}"
        repo = owner_repo(git(checkout, "remote", "get-url", remote_hint))
        kind, name = "tag", ref
    else:
        # A remote-tracking ref names its own remote, and it is what the help
        # text tells the operator to pass, so it is resolved directly. Asking
        # for ITS upstream fails, which is how the first run of this function
        # rejected exactly the ref the documentation recommends.
        remote_ref = subprocess.run(
            ["git", "-C", str(checkout), "rev-parse", "--verify", "--quiet",
             f"refs/remotes/{ref}"],
            capture_output=True, text=True, check=False,
        )
        if remote_ref.returncode == 0:
            remote, _, name = ref.partition("/")
        else:
            tracking = subprocess.run(
                ["git", "-C", str(checkout), "rev-parse", "--abbrev-ref",
                 f"{ref}@{{upstream}}"],
                capture_output=True, text=True, check=False,
            )
            if tracking.returncode != 0 or "/" not in tracking.stdout.strip():
                raise SystemExit(
                    f"FAIL: cannot derive which repository publishes {ref!r}. "
                    "It is not a tag, not a remote-tracking ref, and has no "
                    "tracking ref of its own, so the pin would have to name a "
                    "repository nobody checked. Give --ref a branch that "
                    "tracks a remote, a remote-tracking ref, or a tag plus "
                    "--remote."
                )
            remote, _, name = tracking.stdout.strip().partition("/")
        verify_ref = f"refs/remotes/{remote}/{name}"
        repo = owner_repo(git(checkout, "remote", "get-url", remote))
        kind = "branch"

    contains = subprocess.run(
        ["git", "-C", str(checkout), "merge-base", "--is-ancestor", commit,
         verify_ref],
        capture_output=True, text=True, check=False,
    )
    if contains.returncode != 0:
        raise SystemExit(
            f"FAIL: {commit[:12]} is not reachable from {verify_ref} in "
            f"{checkout}, so a reproducer fetching {name} from {repo} would "
            "not get the bytes this pin describes."
        )
    return repo, name, kind


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--from",
        dest="checkout",
        required=True,
        type=Path,
        help="path to an in-toto/attestation checkout on the predicate branch",
    )
    ap.add_argument(
        "--ref",
        default="HEAD",
        help="ref to vendor from (default HEAD; pass the remote ref to avoid "
        "vendoring from a stale local clone)",
    )
    ap.add_argument(
        "--remote",
        default=None,
        help="remote publishing --ref, required only when --ref is a tag, "
        "which has no tracking ref to derive it from",
    )
    ap.add_argument(
        "--at",
        default=None,
        help="commit to vendor, when it is not the tip of --ref. The pin then "
        "names --ref as the ref a reproducer fetches and --at as the commit "
        "inside it; --ref must still contain it. Defaults to the tip of --ref",
    )
    args = ap.parse_args()

    checkout: Path = args.checkout.expanduser().resolve()
    if not (checkout / ".git").exists():
        raise SystemExit(f"FAIL: {checkout} is not a git checkout")

    # Peeled to a commit. `rev-parse` on an ANNOTATED tag returns the tag
    # OBJECT's sha, and `git show <tagobj>:<path>` dereferences it happily, so
    # the digest check downstream still passed while the pin recorded an id
    # that is not a commit and that `git log` will not show as one. Caught by
    # dry-running the tag the operator is about to cut.
    commit = git(checkout, "rev-parse", f"{args.at or args.ref}^{{commit}}")
    commit_repo, ref_name, ref_kind = locate(
        checkout, args.ref, commit, args.remote
    )

    # Read the bytes from the ref itself rather than the working tree, so an
    # uncommitted local edit can never be vendored under a commit that does not
    # contain it.
    proc = subprocess.run(
        ["git", "-C", str(checkout), "show", f"{commit}:{SPEC_REL}"],
        capture_output=True,
        check=False,
    )
    if proc.returncode != 0:
        raise SystemExit(
            f"FAIL: {SPEC_REL} not present at {commit[:12]}: "
            f"{proc.stderr.decode().strip()}"
        )
    spec_bytes = proc.stdout
    digest = hashlib.sha256(spec_bytes).hexdigest()

    dest = REPO_ROOT / SPEC_REL
    previous = dest.read_bytes() if dest.exists() else b""
    dest.write_bytes(spec_bytes)

    PIN_PATH.write_text(
        json.dumps(
            {
                "upstreamRepo": UPSTREAM_REPO,
                "upstreamPullRequest": UPSTREAM_PR,
                "commitRepo": commit_repo,
                "ref": ref_name,
                "refKind": ref_kind,
                "commit": commit,
                "specPath": SPEC_REL,
                "specDigest": digest,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )

    if previous == spec_bytes:
        print(f"vendored spec unchanged at {commit[:12]} ({digest[:12]}...)")
        print("pin refreshed; no corpus regeneration needed")
        return 0

    mapping = line_map(previous, spec_bytes)
    lines = spec_bytes.decode("utf-8", "replace").splitlines()
    moved = remap_citations(mapping, lines)
    moved_anchors = remap_anchors(mapping, lines)

    print(f"vendored {SPEC_REL} at {commit[:12]} ({digest[:12]}...)")
    if moved:
        print(f"remapped {moved} spec:NNN line citation(s) onto the new line numbers")
    if moved_anchors:
        print(f"remapped {moved_anchors} Lnnn anchor(s) onto the new line numbers")

    # Re-pin here rather than leaving it to the operator. The citations rotted
    # in the first place because keeping them current was a manual step beside
    # an automatic one, and a ledger that has to be refreshed by hand is the
    # same bet with an extra file in it.
    #
    # Both ledgers are synced, because both spellings are remapped above and a
    # remap is exactly when a citation can come off its subject. A sync is
    # allowed to refuse: it compares each moved citation against the revision
    # its ledger was pinned to and will not write one that came off prose still
    # present in the document, which is the shape a mis-aimed remap has. When it
    # refuses, the spec is already vendored and both spellings are already
    # remapped; the citations it names are corrected by hand and the sync run
    # again, so re-vendoring stays one command in the ordinary case and stops at
    # the point of doubt in the case that matters.
    failed = [gate for gate in SYNCED_GATES if not resync(gate)]
    if failed:
        print(
            "\nFAIL: the spec is vendored and both spellings are remapped, but "
            f"{' and '.join(failed)} did not write its ledger. Correct the "
            "citations named above, then run that script with --sync.",
            file=sys.stderr,
        )
        return 1

    print("NORMATIVE CHANGE: regenerate the corpus, then run")
    print("  python3 vectors/gen_manifest.py")
    print("and add a suiteRevision section to vectors/CHANGES.md.")
    return 0


# Source files carrying `spec:NNN` citations into the vendored copy.
CITING_GLOBS = (
    "aee/*.go",
    "cmd/*/*.go",
    "witnessattestor/*.go",
    "packaging/*.py",
    "vectors/*/*.py",
)
CITATION_RE = re.compile(r"spec:(\d+(?:-\d+)?(?:\s*,\s*\d+(?:-\d+)?)*)")

# The corpus cites the same file a second way, as `Lnnn` and `Lnnn-mmm` anchors
# in the vector generator, the interpretation registries and the prose that
# reads them. The two spellings are one citation with two audiences: `spec:NNN`
# sits in code comments, `Lnnn` sits in tables a reader scans. Only the first
# was remapped for a while, and the second rotted at the first re-vendor that
# inserted a paragraph, which is how thirty-one anchors came to address prose
# they were never drawn against. Anything carrying an anchor is listed here.
ANCHOR_PATHS = (
    "vectors/reject/gen_invalid_vectors.py",
    "vectors/interpretation-decisions.json",
    "vectors/coverage-unforced.json",
    "vectors/CHANGES.md",
    "docs/interpretation-decisions-open.md",
    # The accept generator's anchor map, missed here for the same reason it was
    # missed by the anchor gate: an accept vector citing a span is a recent
    # shape, and every list of "the files that carry anchors" was written before
    # there was one. It rotted the quietest way available -- the anchor was in
    # no ledger, so a re-vendor that moved the line would have left it pointing
    # at whatever prose arrived, and no check anywhere would have said so. Its
    # index is generated from this file and is regenerated rather than remapped,
    # which is why only the source is listed.
    "vectors/accept/gen_valid_vectors.py",
    # The reading ledger and the document about it address the specification the
    # same way, and both were missed here for exactly as long as the anchor
    # spelling was. They rot differently from the files above, which is why the
    # omission survived: ``spec/READINGS.toml`` keys each declaration on a digest
    # of the sentence text and carries the line only to find it by, so a stale
    # line does not silently excuse the wrong sentence -- it stops excusing
    # anything, and every obligation the ledger had dispositioned reappears as
    # uncited on the first re-vendor that moves it. That is a loud failure in
    # scripts/reading-differential.py rather than a quiet one, but it is a
    # failure the remap is supposed to prevent and did not.
    "spec/READINGS.toml",
    "docs/UNCITED-OBLIGATIONS.md",
)
ANCHOR_RE = re.compile(r"\bL(\d+(?:-\d+)?)\b")


def line_map(old: bytes, new: bytes) -> dict[int, int]:
    """Map 1-based line numbers in `old` to their new position in `new`.

    The diff is computed over NON-BLANK lines only, then blank lines are
    interpolated back in. A blank line is not an anchor: it is identical to
    every other blank line in the document, so a sequence matcher pairs it with
    whichever one balances the alignment, and a citation whose endpoint lands on
    one gets carried hundreds of lines away from its subject. Matching on
    content and interpolating the gaps keeps every citation attached to the
    prose it cites.

    Lines the edit deleted or replaced map to the start of the block that
    replaced them, which is the closest honest answer for a citation pointing
    into prose that no longer exists.
    """
    a = old.decode("utf-8", "replace").splitlines()
    b = new.decode("utf-8", "replace").splitlines()
    ai = [i for i, ln in enumerate(a) if ln.strip()]
    bi = [j for j, ln in enumerate(b) if ln.strip()]
    sm = SequenceMatcher(None, [a[i] for i in ai], [b[j] for j in bi], autojunk=False)

    mapping: dict[int, int] = {}
    for tag, i1, i2, j1, _j2 in sm.get_opcodes():
        if tag == "equal":
            for k in range(i2 - i1):
                mapping[ai[i1 + k] + 1] = bi[j1 + k] + 1
        elif tag in ("replace", "delete"):
            target = bi[j1] + 1 if j1 < len(bi) else len(b)
            for k in range(i1, i2):
                mapping[ai[k] + 1] = target

    # Interpolate the blank lines: carry each one the same distance its nearest
    # preceding non-blank neighbour moved, so a range endpoint on a blank line
    # stays adjacent to its own paragraph.
    delta = 0
    for i in range(1, len(a) + 1):
        if i in mapping:
            delta = mapping[i] - i
        else:
            mapping[i] = min(max(i + delta, 1), len(b))
    return mapping


def rewrite(
    paths: list[Path],
    pattern: re.Pattern[str],
    prefix: str,
    mapping: dict[int, int],
    lines: list[str],
) -> int:
    """Rewrite every citation of one spelling in `paths`, and report how many
    tokens moved."""
    moved = 0
    for path in paths:
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8")

        def sub(m: re.Match[str]) -> str:
            nonlocal moved
            token = remap_token(m.group(1), mapping, lines)
            if token != m.group(1):
                moved += 1
            return f"{prefix}{token}"

        updated = pattern.sub(sub, text)
        if updated != text:
            path.write_text(updated, encoding="utf-8")
    return moved


def remap_citations(mapping: dict[int, int], lines: list[str]) -> int:
    """Rewrite every `spec:NNN` citation in the citing sources onto the new
    line numbers, and report how many tokens moved.

    Line-number citations into a file that is periodically re-vendored rot by
    construction: the spec gains a paragraph upstream and every pointer below it
    silently addresses the wrong prose. Nothing in this repository checked them,
    and a wrong pointer is worse than none, because it reads as evidence that a
    rule was implemented against a passage it was not. Remapping here makes the
    citations follow the content they cite, so re-vendoring cannot rot them; the
    rewrite lands in the same commit as the spec change and is reviewed as a
    diff like anything else.
    """
    paths = [p for g in CITING_GLOBS for p in sorted(REPO_ROOT.glob(g))]
    return rewrite(paths, CITATION_RE, "spec:", mapping, lines)


def remap_anchors(mapping: dict[int, int], lines: list[str]) -> int:
    """Rewrite every `Lnnn` anchor onto the new line numbers.

    The anchors address the vendored copy exactly as the `spec:NNN` citations
    do, so they move with the prose for exactly the same reason. Remapping keeps
    the corpus in the coordinate frame of the commit the vendor pin names: the
    anchors and the pin describe one revision, and neither is free to drift from
    the other between re-vendorings.

    Generated files are not listed and are not rewritten here. They carry the
    anchors their sources carry, so regenerating them after this runs is what
    moves them, and ``scripts/spec-anchor-gate.py`` fails if that regeneration
    was skipped.
    """
    paths = [REPO_ROOT / p for p in ANCHOR_PATHS]
    return rewrite(paths, ANCHOR_RE, "L", mapping, lines)


def snap(n: int, lines: list[str], *, forward: bool) -> int:
    """Move a citation endpoint off a blank line onto real prose.

    A blank line carries nothing, so an endpoint on one is either a range that
    overshot its paragraph or a pointer that was always slightly wrong. A range
    start snaps forward to the first line with content and a range end snaps
    back to the last, which keeps the range covering exactly the prose it was
    drawn around.
    """
    total = len(lines)
    n = min(max(n, 1), total)
    step = 1 if forward else -1
    while 1 <= n <= total and not lines[n - 1].strip():
        n += step
    return min(max(n, 1), total)


def remap_token(token: str, mapping: dict[int, int], lines: list[str]) -> str:
    """Rewrite one citation token (`115`, `115-118`, `67-70,627`) onto the new
    line numbers, preserving the token's own comma spacing."""
    total = len(lines)
    parts: list[str] = []
    for part in (p.strip() for p in token.split(",")):
        if "-" in part:
            lo, hi = (int(x) for x in part.split("-", 1))
            nlo = snap(min(mapping.get(lo, lo), total), lines, forward=True)
            nhi = max(snap(min(mapping.get(hi, hi), total), lines, forward=False), nlo)
            parts.append(f"{nlo}-{nhi}" if nhi != nlo else str(nlo))
        else:
            n = int(part)
            parts.append(str(snap(min(mapping.get(n, n), total), lines, forward=True)))
    return ", ".join(parts) if ", " in token else ",".join(parts)


if __name__ == "__main__":
    sys.exit(main())
