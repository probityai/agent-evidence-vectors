#!/usr/bin/env python3
"""Refuse a push whose HISTORY carries a private path, a dossier name or a product name.

The tree scans beside this one (`forbidden-word-scan.py`, the tool-state and
home-path steps in CI) read the tree at one revision. A string that one commit
adds and a later commit removes is invisible to every one of them, and that is
exactly how four commits carrying a home directory, an internal dossier name and
a product name reached a public repository in 2026-09: the tip was clean, the
history was not. This scans EVERY commit in the range being pushed, added lines
and commit messages both.

Invocation, as a pre-push hook (git writes one line per ref on stdin):

    <local ref> <local sha> <remote ref> <remote sha>

or by hand / from CI:

    scripts/pre-push-identity-scan.py --range <old>..<new>
    scripts/pre-push-identity-scan.py --recent 50      # the last 50 commits of HEAD

Exit codes are three-valued on purpose, because "found nothing" and "could not
look" must never print the same way:

    0  scanned, nothing found (the scanned-commit count is printed)
    1  scanned, at least one hit (commit, file and line are printed)
    2  did not scan -- malformed stdin, a remote sha this clone does not hold,
       a missing rule sidecar, or git failing

What is matched, and where each rule comes from:

  * IDENTITY -- the first-party product names, including identifier forms such
    as a heredoc sentinel or an environment-variable name built on the name.
    The word list is the one `build-public-admission.py` (private tooling)
    compiles as `IDENTITY`, widened to the identifier forms its two outbound
    gates (`slack-send.py check_identity_leak`, `gh-outbound-gate.py`) added
    after a sentinel walked through a word-boundary match. The words are held
    hex-encoded below: this file is itself scanned by the salted-digest guard
    (`no-internal-drafts.yml`), and a scanner that spells what it forbids
    refuses its own commit.
  * ABSOLUTE_HOME -- an absolute home directory on either desktop OS.
  * DOSSIER -- the private research tree's numbered dossier directories.
  * EVERY DECODED VIEW of an added line or a commit message, not only its text.
    Signed statements are the product and a signed statement carries its payload
    base64-encoded, so a forbidden string inside a payload used to sit in a file
    we publish while every rule above read past it. Measured, not argued: a range
    carrying 31 statement files whose signed payloads each held a forbidden host
    produced 31 findings, 20 naming plain-text files and NONE naming anything
    under `statements/`; the push was refused only because a plain-text copy
    happened to sit in the generator beside the encoded ones. `_decoding.views`
    decodes base64 (both alphabets, padded or not), hex and percent-encoding,
    follows nesting, and every rule above is applied to what comes back. A
    finding names the layers crossed and the JSON key path, so a reader learns
    where the string sits, and not only which file held it.
  * The salted-digest sidecar `.githooks/commit-msg.forbidden-words`, loaded
    exactly as `scripts/forbidden-word-scan.py` loads it (that function is
    copied here verbatim, never imported, so this hook has no import path
    to break when it runs from a detached worktree).

Nothing matched is ever echoed. Printing it would reproduce the string into a
CI log or terminal scrollback, committing in the failure report the leak the
rule exists to prevent.
"""

from __future__ import annotations

import argparse
import hashlib
import re
import subprocess
import sys
from pathlib import Path

# A sibling module in this directory, resolved from this file and never from
# the caller's path, so the hook still imports it when git runs it from a
# detached worktree. The same insert-then-import is how scripts/forcing-gate.py
# reaches scripts/_lockfile.py. The sidecar loader below is still copied rather
# than imported, for the reason its own comment gives.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from _decoding import GUARD_MATERIAL, GUARD_SPANS, views  # noqa: E402

HOOK_DIR = Path(__file__).resolve().parent.parent / ".githooks"
SIDECAR = HOOK_DIR / "commit-msg.forbidden-words"
ZERO_SHA = re.compile(r"^0+$")


def _hex(*words: str) -> str:
    """Decode hex-held pattern fragments into one alternation."""
    return "|".join(bytes.fromhex(w).decode("ascii") for w in words)


# Source: the `IDENTITY` pattern at line 36 of the private `build-public-admission.py`
# (three product names, case-insensitive), plus the fourth term the Slack and
# GitHub outbound gates match with `-`, `_` or space separators. The bare names
# already cover the heredoc-sentinel, identifier and `.io`-domain forms those
# gates were widened for. Held as hex for the reason given in the docstring.
IDENTITY_SPANS = (
    "67657470726f62697479",
    "70726f62697479",
    "6d617463686c6f636b",
    "6d63705b2d5f205d746573745b2d5f205d746f6f6c6b6974",
)
IDENTITY = re.compile(_hex(*IDENTITY_SPANS), re.IGNORECASE)
ABSOLUTE_HOME = re.compile(r"^\+.*(/home/[a-z]+/|/Users/[A-Za-z]+/)")
DOSSIER = re.compile(r"research/[0-9]{3}-[a-z0-9-]+")

RULES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("first-party product name", IDENTITY),
    ("absolute home directory", ABSOLUTE_HOME),
    ("private dossier name", DOSSIER),
)

# The same three rules over text that carries no diff marker: a commit message,
# and the decoded view of an added line. `ABSOLUTE_HOME` is anchored to the `+`
# of a diff line, so it is restated here unanchored, not reused, and the
# order matches the one the message scan has always printed in.
HOME_ANYWHERE = re.compile(r"(/home/[a-z]+/|/Users/[A-Za-z]+/)")
BARE_RULES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("first-party product name", IDENTITY),
    ("private dossier name", DOSSIER),
    ("absolute home directory", HOME_ANYWHERE),
)


# The organisation that owns these repositories is named in their own URLs, and a
# URL cannot avoid naming its owner. The span is held hex-encoded because this
# file is itself scanned by the guards it belongs to, and it is kept here rather
# than only in the sidecar because the declared-spans self-check below must know
# that this name is ruled on deliberately rather than by omission.
OWNER_SPAN = "70726f626974796169"

# The permit that lets this repository name its own URLs is held in ONE place,
# `.githooks/commit-msg.permitted-paths`, and read by the three guards that rule
# on the same strings: this scanner (pushed history), scripts/forbidden-word-scan.py
# (tracked content) and .githooks/commit-msg (commit messages). Until 2026-09 the
# two scanners each held a hand-copied regex and the hook held none, so the hook
# refused a Go module path the scanners explicitly permitted and a module-path
# rename could not describe itself. A permit is the one rule shape that can only
# ever loosen, so it gets one definition, and the loader below is small enough
# that copying IT costs nothing while copying the PATTERN cost a day.
#
# An absent or malformed sidecar is exit 2, never a silent run without the
# permit: "the rule surface failed to load" and "the rule surface says no" must
# not print the same way. The sidecar carries its own format and argument.
PERMIT_SIDECAR = HOOK_DIR / "commit-msg.permitted-paths"


def load_permits() -> list[re.Pattern[str]]:
    """Compile every permit in the sidecar, or refuse to run."""
    if not PERMIT_SIDECAR.is_file():
        print(f"identity-scan: no permit sidecar at {PERMIT_SIDECAR}", file=sys.stderr)
        raise SystemExit(2)
    permits: list[re.Pattern[str]] = []
    for number, raw in enumerate(
        PERMIT_SIDECAR.read_text(encoding="utf-8").splitlines(), start=1
    ):
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        fields = raw.split("\t")
        if len(fields) != 2:
            print(
                f"{PERMIT_SIDECAR}:{number}: expected '<hex><TAB><regex>'",
                file=sys.stderr,
            )
            raise SystemExit(2)
        encoded, expression = fields[0].strip(), fields[1].strip()
        if not re.fullmatch(r"(?:[0-9a-f]{2})+", encoded) or not expression:
            print(
                f"{PERMIT_SIDECAR}:{number}: first field must be lowercase hex pairs "
                "and the pattern must not be empty",
                file=sys.stderr,
            )
            raise SystemExit(2)
        try:
            permits.append(
                re.compile(
                    bytes.fromhex(encoded).decode("ascii") + expression, re.IGNORECASE
                )
            )
        except (UnicodeDecodeError, re.error) as exc:
            print(f"{PERMIT_SIDECAR}:{number}: unusable permit: {exc}", file=sys.stderr)
            raise SystemExit(2) from exc
    if not permits:
        print(f"{PERMIT_SIDECAR}: carries no permit", file=sys.stderr)
        raise SystemExit(2)
    return permits


PERMITS = load_permits()

# The spans above are rule material, and decoding is what made that a problem:
# the first run of this scan after the decoding step was added refused this
# file's own commit, naming the line the word list is built from.
# `_decoding.material` explains why the answer is the literals and not the
# path, and `_decoding.GUARD_SPANS` explains why one list covers every guard
# in place of one list each. This check is what keeps that list honest: a span
# used here and not declared there would be refused by the sibling scan that
# reads this file, so the mismatch stops the guard and not a push.
UNDECLARED = (set(IDENTITY_SPANS) | {OWNER_SPAN}) - set(GUARD_SPANS)
if UNDECLARED:
    print(
        f"identity-scan: {len(UNDECLARED)} rule span(s) are not declared in "
        "_decoding.GUARD_SPANS; add them there so every guard exempts them alike",
        file=sys.stderr,
    )
    raise SystemExit(2)


def permit(line: str) -> str:
    """Blank owner-qualified repository paths, preserving every offset.

    The filler is the same length as what it replaces, so a later hit on the same
    line is still reported at its true position, and a second mention that is NOT
    owner-qualified still reaches the rules below.
    """
    for pattern in PERMITS:
        line = pattern.sub(lambda match: "." * len(match.group(0)), line)
    return line


# ---------------------------------------------------------------------------
# Salted-digest sidecar. `_lengths`, `_digest` and `load` are copied VERBATIM
# from scripts/forbidden-word-scan.py in this repository so the two scanners
# read one rule file the same way and cannot drift apart.
# ---------------------------------------------------------------------------
def _lengths(marker: str, line: str, number: int) -> list[int]:
    """Parse one `# lengths-*:` header, or refuse."""
    field = line[len(marker) :].strip()
    if not re.fullmatch(r"\d+(,\d+)*", field):
        print(f"{SIDECAR}:{number}: malformed {marker}", file=sys.stderr)
        raise SystemExit(2)
    return sorted({int(n) for n in field.split(",")})


def _digest(raw: str, number: int) -> tuple[str, str]:
    """Parse one `<sha256hex><TAB><label>` line, or refuse."""
    if "\t" not in raw:
        print(f"{SIDECAR}:{number}: expected '<digest><TAB><label>'", file=sys.stderr)
        raise SystemExit(2)
    digest, _, label = raw.partition("\t")
    digest = digest.strip().lower()
    if not re.fullmatch(r"[0-9a-f]{64}", digest):
        print(f"{SIDECAR}:{number}: not a sha256 digest", file=sys.stderr)
        raise SystemExit(2)
    return digest, label.strip() or "forbidden token"


def load() -> tuple[str, list[int], list[int], dict[str, str]]:
    if not SIDECAR.is_file():
        print(f"forbidden-word-scan: no sidecar at {SIDECAR}", file=sys.stderr)
        raise SystemExit(2)
    salt = ""
    widths: dict[str, list[int]] = {"i": [], "s": []}
    table: dict[str, str] = {}
    for number, raw in enumerate(
        SIDECAR.read_text(encoding="utf-8").splitlines(), start=1
    ):
        line = raw.strip()
        if not line:
            continue
        if line.startswith("#"):
            if line.startswith("# salt:"):
                salt = line[len("# salt:") :].strip()
            for kind, marker in (("i", "# lengths-i:"), ("s", "# lengths-s:")):
                if line.startswith(marker):
                    widths[kind] = _lengths(marker, line, number)
            continue
        digest, label = _digest(raw, number)
        table[digest] = label
    if not salt or not table or not (widths["i"] or widths["s"]):
        print(
            f"{SIDECAR}: needs a '# salt:' line, at least one '# lengths-*:' "
            "line and at least one digest",
            file=sys.stderr,
        )
        raise SystemExit(2)
    return salt, widths["i"], widths["s"], table


# ---------------------------------------------------------------------------
# Matching
# ---------------------------------------------------------------------------
class Sidecar:
    def __init__(self) -> None:
        self.salt, self.nocase, self.cased, self.table = load()

    def labels(self, line: str) -> list[str]:
        """Every sidecar label whose word occurs in `line`, each once."""
        found: list[str] = []
        seen: set[str] = set()
        for haystack, lengths in ((line.lower(), self.nocase), (line, self.cased)):
            for width in lengths:
                for start in range(0, len(haystack) - width + 1):
                    digest = hashlib.sha256(
                        (self.salt + haystack[start : start + width]).encode("utf-8")
                    ).hexdigest()
                    label = self.table.get(digest)
                    if label is not None and digest not in seen:
                        seen.add(digest)
                        found.append(label)
        return found


def _git(*args: str) -> str:
    done = subprocess.run(["git", *args], capture_output=True, check=False)
    if done.returncode != 0:
        print(
            f"identity-scan: git {' '.join(args[:3])} failed: "
            f"{done.stderr.decode('utf-8', 'replace').strip()}",
            file=sys.stderr,
        )
        raise SystemExit(2)
    # `replace`, not `surrogateescape`: a byte that is not UTF-8 becomes U+FFFD,
    # which every later encode accepts. A lone surrogate from `surrogateescape`
    # crashed the digest step on this repository's own history at commit 12
    # of 688, and a scanner that crashes reports nothing about the rest.
    return done.stdout.decode("utf-8", "replace")


def _holds(sha: str) -> bool:
    return subprocess.run(
        ["git", "cat-file", "-e", f"{sha}^{{commit}}"], capture_output=True, check=False
    ).returncode == 0


def _bare_hits(where: str, text: str, sidecar: Sidecar) -> list[str]:
    """Every rule hit in one piece of text that carries no diff marker."""
    hits: list[str] = []
    scanned = permit(text)
    for label, rule in BARE_RULES:
        if rule.search(scanned):
            hits.append(f"{where}: {label} (text withheld)")
    for label in sidecar.labels(scanned):
        hits.append(f"{where}: {label} (word withheld)")
    return hits


def _decoded_hits(where: str, text: str, sidecar: Sidecar) -> list[str]:
    """Every rule hit in every decoded view of `text`.

    The layers crossed are printed and the matched string is not, which is the
    same trade the rest of this file makes: a reader needs to know that the hit
    is in the base64 `payload` of an envelope and not in its prose, and does
    not need the string reproduced into a CI log to act on it.
    """
    hits: list[str] = []
    for layers, decoded in views(text, GUARD_MATERIAL):
        hits.extend(_bare_hits(f"{where} [{layers}]", decoded, sidecar))
    return hits


def _message_hits(sha: str, message: str, sidecar: Sidecar) -> list[str]:
    """Every rule hit in one commit message, one entry per matching line and rule."""
    hits: list[str] = []
    for number, line in enumerate(message.splitlines(), start=1):
        where = f"{sha[:12]} (commit message):{number}"
        hits.extend(_bare_hits(where, line, sidecar))
        hits.extend(_decoded_hits(where, line, sidecar))
    return hits


def _scan_messages(rev_args: list[str], sidecar: Sidecar) -> list[str]:
    """Commit messages first: three of this repository's own messages once
    carried a product name, and a message is not a diff line."""
    hits: list[str] = []
    for record in _git("log", "--format=%H%x00%B%x01", *rev_args).split("\x01"):
        if "\x00" not in record:
            continue
        sha, _, message = record.partition("\x00")
        hits.extend(_message_hits(sha.strip(), message, sidecar))
    return hits


def _scan_added_lines(rev_args: list[str], sidecar: Sidecar) -> list[str]:
    """Every ADDED line of every commit. `-U0` keeps context lines out of the
    diff so a hit is always on a line the commit itself introduced."""
    hits: list[str] = []
    sha = ""
    path = ""
    number = 0
    for raw in _git(
        "log", "-p", "-U0", "--no-color", "--no-ext-diff", "--format=%x02%H", *rev_args
    ).splitlines():
        if raw.startswith("\x02"):
            sha = raw[1:].strip()
            path = ""
            continue
        if raw.startswith("+++ "):
            path = raw[4:]
            path = path[2:] if path.startswith("b/") else path
            continue
        if raw.startswith("@@"):
            found = re.match(r"@@ -\S+ \+(\d+)", raw)
            number = int(found.group(1)) - 1 if found else 0
            continue
        if not raw.startswith("+") or raw.startswith("+++"):
            continue
        number += 1
        where = f"{sha[:12]} {path}:{number}"
        scanned = permit(raw)
        for label, rule in RULES:
            if rule.search(scanned):
                hits.append(f"{where}: {label} (text withheld)")
        for label in sidecar.labels(scanned[1:]):
            hits.append(f"{where}: {label} (word withheld)")
        hits.extend(_decoded_hits(where, scanned[1:], sidecar))
    return hits


def scan_range(rev_args: list[str], sidecar: Sidecar) -> tuple[int, list[str]]:
    """Scan every commit `git log <rev_args>` reaches. Returns (commits scanned, hits)."""
    commits = [c for c in _git("rev-list", *rev_args).split() if c]
    if not commits:
        return 0, []
    return len(commits), _scan_messages(rev_args, sidecar) + _scan_added_lines(rev_args, sidecar)


def ranges_from_stdin(lines: list[str]) -> list[list[str]]:
    """Turn the pre-push protocol lines into `git log` revision arguments."""
    ranges: list[list[str]] = []
    for line in lines:
        if not line.strip():
            continue
        fields = line.split()
        if len(fields) != 4:
            print(f"identity-scan: malformed pre-push line: {line.rstrip()!r}", file=sys.stderr)
            raise SystemExit(2)
        _local_ref, local_sha, _remote_ref, remote_sha = fields
        if ZERO_SHA.match(local_sha):
            continue  # a deletion moves no commits
        if not _holds(local_sha):
            print(f"identity-scan: this clone does not hold {local_sha}", file=sys.stderr)
            raise SystemExit(2)
        if ZERO_SHA.match(remote_sha):
            # A NEW ref: everything it carries that no remote-tracking ref of
            # origin already holds is new to the remote.
            ranges.append([local_sha, "--not", "--remotes=origin"])
            continue
        if not _holds(remote_sha):
            print(
                f"identity-scan: the remote's {remote_sha[:12]} is not in this clone; "
                "fetch first so the push range can be computed",
                file=sys.stderr,
            )
            raise SystemExit(2)
        ranges.append([f"{remote_sha}..{local_sha}"])
    return ranges


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument("--range", action="append", default=[], metavar="OLD..NEW",
                        help="a revision range to scan; stdin is not read")
    parser.add_argument("--recent", type=int, metavar="N",
                        help="scan the last N commits reachable from HEAD")
    args = parser.parse_args(argv[1:])

    sidecar = Sidecar()
    ranges: list[list[str]] = [[r] for r in args.range]
    if args.recent is not None:
        ranges.append([f"--max-count={args.recent}", "HEAD"])
    if not ranges:
        ranges = ranges_from_stdin(sys.stdin.read().splitlines())
    if not ranges:
        print("identity-scan: no revision named (deletions only); nothing to scan")
        return 0

    total = 0
    hits: list[str] = []
    for rev_args in ranges:
        count, found = scan_range(rev_args, sidecar)
        total += count
        hits.extend(found)

    for hit in hits:
        print(hit)
    if hits:
        print(
            f"identity-scan: {len(hits)} hit(s) across {total} commit(s). A private path, "
            "dossier name or product name is in this push's HISTORY, not only its tip; "
            "rewrite the commits before pushing.",
            file=sys.stderr,
        )
        return 1
    print(f"identity-scan: {total} commit(s) scanned, clean")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
