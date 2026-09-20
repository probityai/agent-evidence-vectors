#!/usr/bin/env python3
"""Tests for the owner-path permit that three guards share.

WHY THIS FILE EXISTS. The guards refuse first-party names in this public,
product-neutral repository. The organisation that owns the repository is named
in its own clone URL, its badge targets and its citation file, and a URL cannot
avoid naming its owner, so one narrow permit was added: the handle passes where
a slash and one of the three repository names follow it, and nowhere else.

A permit on a refusal is the one change that can only ever loosen, and a
loosening that goes unnoticed is indistinguishable from the control working. So
every case below asserts a direction. The permitted shapes are here to prove the
push is possible at all; the refused ones are the point, and they outnumber them.

THREE guards rule on these strings and every one of them is exercised below,
against the same two populations: `pre-push-identity-scan.py` on pushed history,
`forbidden-word-scan.py` on tracked content, and `.githooks/commit-msg` on
commit messages. They read ONE permit, `.githooks/commit-msg.permitted-paths`,
because they did not always: the two scanners each held a hand-copied regex and
the hook held none, so the hook refused a Go module path the scanners explicitly
permitted, and the commit that renamed the module path could not name the path
it was renaming. A disagreement between guards is invisible from inside any one
of them, which is what this file is for.

The tokens are built from hex at run time, exactly as the sidecar holds its own,
so this file can be read by anyone without carrying the strings it is about.

Usage: python3 scripts/pre-push-identity-scan-test.py
Exit 0 when every case holds; 1 on a summary of the failures.
"""

from __future__ import annotations

import importlib.util
import subprocess
import sys
import tempfile
from collections.abc import Callable, Sequence
from pathlib import Path

HERE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("scan", HERE / "pre-push-identity-scan.py")
assert _spec is not None and _spec.loader is not None
scan = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(scan)


def _hex(value: str) -> str:
    return bytes.fromhex(value).decode("ascii")


OWNER = _hex("70726f626974796169")
COMPANY = _hex("70726f62697479")
SITE = _hex("67657470726f62697479") + ".dev"
OTHER = _hex("6d617463686c6f636b")

_sidecar = scan.Sidecar()


def refused(line: str) -> bool:
    """Whether the scanner would report this as an added line."""
    scanned = scan.permit("+" + line)
    if any(rule.search(scanned) for _, rule in scan.RULES):
        return True
    return bool(_sidecar.labels(scanned[1:]))


PERMITTED = (
    ("an owner-qualified path", f"{OWNER}/agent-evidence-vectors"),
    ("a web URL", f"https://github.com/{OWNER}/agent-evidence-vocabulary/blob/main/README.md"),
    ("an ssh URL", f"git@github.com:{OWNER}/agent-evidence-admission.git"),
    ("a package source URL", f"git+https://github.com/{OWNER}/agent-evidence-vectors@v0.11.1"),
    ("an action reference", f"uses: {OWNER}/agent-evidence-vectors@v0.11.1"),
)

REFUSED = (
    ("the handle with no repository after it", f"maintainer of the {OWNER} organisation"),
    ("the handle before a repository not ours", f"{OWNER}/something-else"),
    ("the handle ending a sentence", f"the owner is {OWNER}."),
    ("an organisation page, which is not a repository URL", f"https://github.com/{OWNER}"),
    ("the company word alone", f"built by {COMPANY} in 2026"),
    (
        "the company word beside a permitted path",
        f"{OWNER}/agent-evidence-vectors run by {COMPANY}",
    ),
    ("the website in a sentence", f"see {SITE} for more"),
    ("the website inside a link", f"[docs](https://{SITE}/predicate/v1/)"),
    ("the website bare", SITE),
    ("another first-party product", f"the {OTHER} runtime"),
)


# The sibling scanner. `forbidden-word-scan.py` reads tracked CONTENT where the
# hook above reads pushed HISTORY, and the two share one rule file, so they need
# the same permit or the repository passes one guard and fails the other. It is
# exercised through a file because that is its only input. Where a repository
# does not carry it, these cases report as skipped and never as passed.
CONTENT_SCANNER = HERE / "forbidden-word-scan.py"


def content_refuses(line: str) -> bool:
    """Whether the content scanner refuses a file containing `line`."""
    with tempfile.TemporaryDirectory() as raw:
        probe = Path(raw) / "probe.txt"
        probe.write_text(line + "\n", encoding="utf-8")
        done = subprocess.run(
            [sys.executable, str(CONTENT_SCANNER), str(probe)],
            capture_output=True,
            text=True,
            timeout=180,
            check=False,
        )
    return done.returncode != 0


# The commit-message gate, the third reader of the same permit. It is exercised
# through a message file because that is its contract with git, and every case
# rides in the BODY under a fixed clean subject: the subject-length rule would
# otherwise refuse the longer URLs for a reason that has nothing to do with the
# permit, and a refusal counted for the wrong reason is a case that proves
# nothing. `_hook_control` asserts that fixed message passes on its own, so any
# refusal below is attributable to the line under test and not to the harness.
HOOK = HERE.parent / ".githooks" / "commit-msg"
HOOK_SUBJECT = "chore: probe the identity permit"


def _hook(body: str) -> int:
    with tempfile.TemporaryDirectory() as raw:
        message = Path(raw) / "COMMIT_EDITMSG"
        message.write_text(f"{HOOK_SUBJECT}\n\n{body}\n", encoding="utf-8")
        done = subprocess.run(
            [sys.executable, str(HOOK), str(message)],
            capture_output=True,
            text=True,
            timeout=180,
            check=False,
        )
        return done.returncode


def hook_refuses(line: str) -> bool:
    """Whether the commit-message gate refuses a message whose body is `line`."""
    return _hook(line) != 0


def _hook_control() -> list[str]:
    """The harness itself must pass a message that names nothing."""
    if _hook("a body that names nothing at all") != 0:
        return [
            "the commit-message harness failed its own control: a message naming "
            "nothing was refused, so every hook case below would be meaningless"
        ]
    return []


def _run_cases(
    refuses: Callable[[str], bool],
    permitted: Sequence[tuple[str, str]],
    refused_cases: Sequence[tuple[str, str]],
    label: str,
) -> tuple[int, list[str]]:
    """Run one scanner over both populations, and return its count and failures.

    The count is of cases that RAN, never of the list handed in: a skipped
    loop must not report full coverage, which is what an earlier version did
    when a mutation emptied the loop and it still printed every case held.

    Both scanners are checked against the same cases, so the loop was written
    twice and `main` went over the complexity ceiling. The bodies were already
    identical apart from which scanner was called and what the line said.
    """
    bad: list[str] = []
    ran = 0
    for what, line in permitted:
        ran += 1
        if refuses(line):
            bad.append(f"{what}{label}: refused, but the permit exists for this shape")
        else:
            print(f"ok   permitted  {what}{label}")
    for what, line in refused_cases:
        ran += 1
        if refuses(line):
            print(f"ok   refused    {what}{label}")
        else:
            bad.append(f"{what}{label}: PASSED, which widens the permit to the bare name")
    return ran, bad


def main() -> int:
    total, failures = _run_cases(refused, PERMITTED, REFUSED, "")
    if CONTENT_SCANNER.exists():
        # A host shape is a URL, which only the history scanner rules on.
        host_only = ("organisation page", "repository not ours")
        for_content = [
            (what, line) for what, line in REFUSED if not any(h in what for h in host_only)
        ]
        more, bad = _run_cases(content_refuses, PERMITTED, for_content, " (content scanner)")
        total += more
        failures += bad
    else:
        print("skip content scanner: this repository does not carry one")
    if HOOK.exists():
        control = _hook_control()
        failures += control
        if not control:
            # Every shape applies here. The content scanner is handed a file and
            # rules on words alone, so the two URL-host shapes mean nothing to
            # it; the hook rules on the same text a human wrote, so a host shape
            # is exactly as refusable in a message as it is in history.
            more, bad = _run_cases(hook_refuses, PERMITTED, REFUSED, " (commit-message gate)")
            total += more
            failures += bad
    else:
        print("skip commit-message gate: this repository does not carry one")
    for line in failures:
        print(f"FAIL {line}", file=sys.stderr)
    print(f"{total - len(failures)}/{total} cases held")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
