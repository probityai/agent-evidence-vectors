#!/usr/bin/env python3
"""Prove the vendor remap carries every anchor onto the SAME TEXT it named.

``vendor-spec.py`` rewrites every ``Lnnn`` anchor and every ``spec:NNN``
citation onto new line numbers when the specification is re-vendored. That
rewrite has never been exercised against an insertion, and an insertion is
what the next re-vendor carries: an added paragraph shifts every line below it,
and a reworded paragraph is a ``replace`` opcode whose lines all collapse onto
the start of whatever replaced them.

The failure that matters is silent. A remap that lands an anchor on
NEIGHBOURING PROSE produces a document where every anchor still resolves, every
gate still passes, and each one addresses text that does not carry its rule --
which is precisely the defect the anchor gate spent a commit closing, arrived at
from the other direction. Nothing downstream can detect it, because a wrong
anchor addresses its wrong text perfectly well.

So this asserts the invariant directly rather than checking that the remap ran:
for every anchor and every citation, the text addressed BEFORE the remap must
equal the text addressed AFTER it. Where the cited text was itself edited, the
anchor cannot land on identical bytes and the case says so explicitly rather
than passing on a substring; those are reported as EDITED and listed, so a
reader sees which rules moved and can check them by eye.

The upstream side is PINNED. spec/VENDOR-PIN.json names a revision and a path,
and the bytes are read out of an object store with `git show` rather than from any
working tree, so this check answers the same way twice at one repository revision
however a sibling clone is being edited meanwhile. It used to read a clone's
working tree, which made its verdict a function of what another lane happened to
be doing; see pinned_upstream for what that cost.

Usage:
  python3 scripts/vendor-remap-test.py            # against the pinned upstream
  python3 scripts/vendor-remap-test.py --synthetic # against constructed edits only

Exit 0 when every anchor survives, 1 when one lands on different prose, 2 when
the question could not be asked -- no pin, no checkout holding the pinned
revision, a path absent from it, an unreadable spec, or a pinned anchor this
script cannot parse. A run that could not ask must never report that the remap is
sound, so none of those is an exit 0.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from types import ModuleType
from typing import NamedTuple

REPO_ROOT = Path(__file__).resolve().parent.parent
SPEC_REL = "spec/predicates/adversarial-execution-evidence.md"
PINS = REPO_ROOT / "spec" / "ANCHOR-PINS.json"
VENDOR_PIN = REPO_ROOT / "spec" / "VENDOR-PIN.json"
#: Where the upstream checkout lives when the pin does not say. Only ever used to
#: locate an OBJECT STORE: no working tree is read through it.
FORK = Path.home() / "Documents" / "git-clones" / "attestation"


def load_vendor() -> ModuleType:
    """Load vendor-spec.py by path: its name is not an importable identifier."""
    path = REPO_ROOT / "scripts" / "vendor-spec.py"
    spec = importlib.util.spec_from_file_location("vendor_spec", path)
    if spec is None or spec.loader is None:
        raise SystemExit(f"REFUSED: cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def pinned_matches(pinned: str, actual: str) -> bool:
    """Whether a line still carries the text a pin recorded for it.

    THE PIN LEDGER TRUNCATES. A long line is stored with a trailing ellipsis,
    so a naive equality check reports that every long-line anchor has come off
    its subject. The first run of this test did exactly that and named a pin
    stale that was perfectly intact -- a false finding about the very ledger the
    test exists to protect, which would have been read as evidence the remap
    was unsound.
    """
    pinned = " ".join(pinned.split())
    actual = " ".join(actual.split())
    if pinned.endswith("..."):
        return actual.startswith(pinned[:-3])
    return pinned == actual


def span_text(lines: list[str], lo: int, hi: int) -> str:
    """The text an anchor addresses, normalised for whitespace only.

    Line numbers are 1-based and inclusive. Out-of-range endpoints are clamped
    rather than raising, because a remap producing an out-of-range endpoint is a
    finding this function's caller must be able to report.
    """
    lo = max(1, min(lo, len(lines)))
    hi = max(1, min(hi, len(lines)))
    if hi < lo:
        lo, hi = hi, lo
    return " ".join(" ".join(lines[lo - 1 : hi]).split())


class Pin(NamedTuple):
    """One pinned anchor: where it points, and what it said when it was pinned.

    ``opens`` and ``closes`` are the strongest available statement of the
    invariant. The ledger does not merely record that an anchor existed at a
    line; it records the TEXT that line carried. So the question after a remap
    is not "did the number change" -- it always does -- but "does the anchor
    still open and close on the words it was pinned to".
    """

    key: str
    lo: int
    hi: int
    opens: str
    closes: str


def anchors_from_pins() -> list[Pin]:
    """Every pinned anchor. The ledger is the authority for which exist: it is
    what the anchor gate re-derives against, so an anchor absent from it is one
    nothing was protecting anyway."""
    if not PINS.is_file():
        raise SystemExit(f"REFUSED: {PINS} is absent, so there are no anchors to test")
    data = json.loads(PINS.read_text(encoding="utf-8"))
    citations = data.get("citations")
    if not isinstance(citations, dict):
        raise SystemExit(
            "REFUSED: the pin ledger has no citations object; its shape changed "
            "and this test would silently check nothing"
        )
    out: list[Pin] = []
    for key, entry in citations.items():
        if not isinstance(entry, dict):
            continue
        token = str(entry.get("anchor", "")).lstrip("L")
        if not token:
            continue
        lo_s, _, hi_s = token.partition("-")
        try:
            lo = int(lo_s)
            hi = int(hi_s) if hi_s else lo
        except ValueError:
            continue
        out.append(
            Pin(key, lo, hi, str(entry.get("opens", "")), str(entry.get("closes", "")))
        )
    return out


def synthetic_pair(old: str) -> str:
    """The two edit shapes the next re-vendor actually carries, applied to a copy.

    An INSERTION of a whole paragraph, which shifts every line below it, and a
    REPLACE of an existing paragraph in place, whose lines collapse onto the
    start of the replacement. Both are constructed here rather than taken from
    the fork so the case runs in a checkout that has no fork beside it.
    """
    lines = old.splitlines()
    cut = len(lines) // 3
    inserted = [
        "",
        "A synthetic paragraph inserted to shift every line below this point,",
        "so the remap is exercised against the shape the next re-vendor carries.",
        "",
    ]
    out = lines[:cut] + inserted + lines[cut:]
    # A replace, further down, so both opcodes appear in one diff.
    at = cut + len(inserted) + (len(lines) - cut) // 2
    if at < len(out):
        out[at] = out[at] + " This clause was appended in place."
    return "\n".join(out) + "\n"


def classify(
    pin: Pin,
    mapping: dict[int, int],
    old_lines: list[str],
    new_lines: list[str],
) -> tuple[str, str]:
    """One anchor's fate under a remap: HELD, EDITED, or MOVED.

    Three outcomes rather than a boolean, because collapsing them loses the one
    that matters. HELD is the anchor landing on the words it was pinned to.
    MOVED is the silent failure: it landed on prose that does not carry its
    rule. EDITED is neither -- the cited text itself changed, so identical bytes
    are impossible, and the honest answer is to name the anchor for a human
    rather than accept a loose match and call the remap sound.
    """
    new_lo = mapping.get(pin.lo, pin.lo)
    new_hi = mapping.get(pin.hi, pin.hi)
    opens_now = span_text(new_lines, new_lo, new_lo)
    closes_now = span_text(new_lines, new_hi, new_hi)
    want_opens = " ".join(pin.opens.split())
    want_closes = " ".join(pin.closes.split())

    if pinned_matches(want_opens, opens_now) and pinned_matches(want_closes, closes_now):
        return "HELD", ""

    old_opens = span_text(old_lines, pin.lo, pin.lo)
    old_closes = span_text(old_lines, pin.hi, pin.hi)
    if not pinned_matches(want_opens, old_opens) or not pinned_matches(
        want_closes, old_closes
    ):
        return "EDITED", f"{pin.key}: pin was already stale before the remap"

    if (
        want_opens
        and opens_now
        and (want_opens.rstrip(".")[:60] in opens_now or opens_now[:60] in want_opens)
    ):
        return (
            "EDITED",
            f"{pin.key}: L{pin.lo}-{pin.hi} -> L{new_lo}-{new_hi} (text edited)",
        )

    return (
        "MOVED",
        f"{pin.key}: L{pin.lo}-{pin.hi} -> L{new_lo}-{new_hi}\n"
        f"      pinned to open on: {want_opens[:100]}\n"
        f"      now opens on:      {opens_now[:100]}",
    )


def check(
    old_text: str,
    new_text: str,
    label: str,
    line_map_fn: Callable[[bytes, bytes], dict[int, int]] | None = None,
) -> int:
    """Check one remap. The mapping function is INJECTED rather than loaded here.

    It used to load the vendor module itself, and that made this uncheckable:
    the mutation proof patched its own module instance while this function
    quietly loaded a fresh one, so a deliberately broken remap was reported
    sound. The proof caught it, which is the entire reason a gate is not trusted
    until a mutation has been shown to make it red.
    """
    remap: Callable[[bytes, bytes], dict[int, int]] = (
        line_map_fn if line_map_fn is not None else load_vendor().line_map
    )
    mapping = remap(old_text.encode("utf-8"), new_text.encode("utf-8"))
    old_lines = old_text.splitlines()
    new_lines = new_text.splitlines()

    try:
        anchors = anchors_from_pins()
    except SystemExit as exc:
        print(str(exc), file=sys.stderr)
        return 2
    if not anchors:
        print(
            "REFUSED: parsed zero anchors from the pin ledger, so this run "
            "would report soundness having tested nothing",
            file=sys.stderr,
        )
        return 2

    moved_wrong: list[str] = []
    edited: list[str] = []
    for pin in anchors:
        verdict, detail = classify(pin, mapping, old_lines, new_lines)
        if verdict == "MOVED":
            moved_wrong.append(detail)
        elif verdict == "EDITED":
            edited.append(detail)

    return report(label, len(anchors), edited, moved_wrong)


def report(
    label: str, total: int, edited: list[str], moved_wrong: list[str]
) -> int:
    """Print one run's outcome and return its exit code.

    Every EDITED anchor is named rather than counted. A reader has to check
    those by eye -- the cited prose changed, so no mechanical comparison can say
    whether the rule survived -- and a bare count would hide which rules moved.
    """
    print(f"[{label}] {total} anchor(s) remapped")
    if edited:
        print(f"[{label}] {len(edited)} anchor(s) address edited prose:")
        for entry in edited:
            print(f"    {entry}")
    if moved_wrong:
        print(
            f"FAIL [{label}]: {len(moved_wrong)} anchor(s) landed on different prose.",
            file=sys.stderr,
        )
        for entry in moved_wrong:
            print(f"  - {entry}", file=sys.stderr)
        return 1
    print(f"OK [{label}]: every anchor addresses the same text after the remap.")
    return 0


def prove_the_instrument(old_text: str, new_text: str) -> int:
    """Show this test RED against a remap that is wrong in the plausible way.

    A check that has only ever passed is not evidence. The failure it must catch
    is not a crash or an exception -- it is a remap that runs cleanly, moves
    every anchor, and lands them a few lines off their subject, which is exactly
    what a naive constant-offset remap does after an insertion: every anchor
    below the insert is short by the inserted length, so each one opens on
    neighbouring prose while the document still looks entirely well-formed.

    So the mutation IS a constant-offset mapping, and this asserts the checker
    reports it as anchors landing on different prose. If this ever passes, the
    checker has stopped discriminating and every green run above it means
    nothing.
    """
    def naive(_old: bytes, _new: bytes) -> dict[int, int]:
        """What a lazy remap does: leave every line number where it was."""
        return {i: i for i in range(1, len(new_text.splitlines()) + 2)}

    rc = check(
        old_text, new_text, "MUTATION: identity map after an insertion", naive
    )

    if rc == 1:
        print("OK [mutation]: the checker refuses a remap that leaves anchors behind.")
        return 0
    print(
        "FAIL [mutation]: an identity map after an insertion was ACCEPTED, so this "
        "test cannot tell a correct remap from a broken one and its passing runs "
        "establish nothing.",
        file=sys.stderr,
    )
    return 1


def pinned_upstream() -> tuple[str | None, str | None]:
    """The upstream page at the PINNED re-vendor target, or why it could not be read.

    Never reads a working tree. `remapTarget.commit` in spec/VENDOR-PIN.json names the
    revision the next re-vendor moves to, and the bytes come out of an object store
    with `git show`, so this check answers the same way twice at one repository
    revision however that clone is being edited meanwhile.

    The target is deliberately NOT `commit` in the same file. That one records what
    the vendored copy already IS -- scripts/spec-drift-gate.py holds the bytes to its
    digest -- and the question here is what the next move would do to every anchor,
    which is a different revision by construction.

    This replaces a read of `FORK / SPEC_REL`, a sibling clone's working tree. On
    2026-09-20 a lane reduced that file from 2322 lines to 278 while amending it three
    times in two hours, and three branches went red at different times; one of them had
    no commits but a run-ledger entry and a fix to an unrelated gate.

    Every failure returns a REASON and the caller exits 2. An absent checkout, an
    unrecorded target, a revision nobody fetched, a path missing from it: each is a
    question that could not be asked, and a check that could not run has not passed.
    """
    if not VENDOR_PIN.is_file():
        return None, (
            f"{VENDOR_PIN.relative_to(REPO_ROOT)} is absent, so no upstream revision is "
            "pinned and there is nothing to compare against."
        )
    try:
        pin = json.loads(VENDOR_PIN.read_text(encoding="utf-8"))
    except ValueError as exc:
        return None, f"{VENDOR_PIN.relative_to(REPO_ROOT)} does not parse: {exc}"

    rel = VENDOR_PIN.relative_to(REPO_ROOT)
    target = pin.get("remapTarget")
    if not isinstance(target, dict) or not isinstance(target.get("commit"), str):
        return None, (
            f"{rel} records no `remapTarget.commit`. That is the revision the next "
            "re-vendor moves to, and without it this check has nothing to compare the "
            "vendored page against. Record it, or run with --synthetic, which asks a "
            "question that needs no upstream."
        )
    revision = target["commit"]
    path = pin.get("specPath")
    if not isinstance(path, str) or not path:
        return None, f"{rel} records no `specPath`."

    if not FORK.is_dir():
        return None, (
            f"no checkout at {FORK}, so the pinned revision {revision[:12]} cannot be "
            f"read. Clone {pin.get('commitRepo', 'the upstream fork')} there."
        )
    present = subprocess.run(
        ["git", "-C", str(FORK), "cat-file", "-e", f"{revision}^{{commit}}"],
        capture_output=True,
        text=True,
        check=False,
    )
    if present.returncode != 0:
        return None, (
            f"{revision[:12]} is not in the object store at {FORK}. It is pinned and has "
            f"to be fetched before this check can be asked: git -C {FORK} fetch "
            f"{pin.get('commitRepo', '<remote>')} {pin.get('ref', revision)}"
        )
    shown = subprocess.run(
        ["git", "-C", str(FORK), "show", f"{revision}:{path}"],
        capture_output=True,
        text=True,
        check=False,
    )
    if shown.returncode != 0:
        return None, (
            f"{path} is not in {revision[:12]}: {shown.stderr.strip()}. The pin names a "
            "revision and a path together; one without the other says nothing."
        )
    return shown.stdout, None


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--synthetic",
        action="store_true",
        help="test only the constructed insertion and replace, skipping the fork",
    )
    args = parser.parse_args()

    vendored = REPO_ROOT / SPEC_REL
    if not vendored.is_file():
        print(f"REFUSED: {vendored} is absent", file=sys.stderr)
        return 2
    old_text = vendored.read_text(encoding="utf-8")

    synthetic = synthetic_pair(old_text)

    # The instrument is proved BEFORE any of its verdicts are reported, so a
    # green run below can never be a checker that stopped discriminating.
    rc = prove_the_instrument(old_text, synthetic)
    if rc != 0:
        return rc

    rc = check(old_text, synthetic, "synthetic insert+replace")
    if rc != 0 or args.synthetic:
        return rc

    upstream, why = pinned_upstream()
    if upstream is None:
        print(f"REFUSED [real re-vendor]: {why}", file=sys.stderr)
        return 2
    return check(old_text, upstream, "real re-vendor")


if __name__ == "__main__":
    raise SystemExit(main())
