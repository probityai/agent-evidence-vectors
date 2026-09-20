#!/usr/bin/env python3
"""Refuse any tracked file containing a word from the salted-hash sidecar.

Companion to the commit-msg hook: the hook covers commit messages, this covers
file contents. Both read `.githooks/commit-msg.forbidden-words`, so there is
one list and no way for the two surfaces to drift apart.

    scripts/forbidden-word-scan.py            # every tracked file
    scripts/forbidden-word-scan.py path ...   # only these

Exit codes are three-valued on purpose, because "found nothing" and "could not
look" must never print the same way:

    0  scanned, nothing found
    1  scanned, at least one hit
    2  did not scan -- missing or malformed sidecar, or git unavailable

A missing sidecar is exit 2, not exit 0. A guard whose rule list failed to load
has not verified anything, and reporting that as clean is how a check quietly
stops being a check. This one scans its own rule file too: there is no plaintext
in it to exempt, which is the whole reason the list is hashed.
"""

from __future__ import annotations

import hashlib
import re
import subprocess
import sys
from pathlib import Path

HOOK_DIR = Path(__file__).resolve().parent.parent / ".githooks"
SIDECAR = HOOK_DIR / "commit-msg.forbidden-words"



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


def tracked_files() -> list[Path]:
    done = subprocess.run(
        ["git", "ls-files", "-z"], capture_output=True, check=False
    )
    if done.returncode != 0:
        print(
            f"forbidden-word-scan: git ls-files failed: "
            f"{done.stderr.decode('utf-8', 'replace').strip()}",
            file=sys.stderr,
        )
        raise SystemExit(2)
    names = done.stdout.decode("utf-8", "surrogateescape").split("\0")
    return [Path(n) for n in names if n]



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
        print(f"forbidden-word-scan: no permit sidecar at {PERMIT_SIDECAR}", file=sys.stderr)
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


def permit(line: str) -> str:
    """Blank owner-qualified repository paths, preserving every offset.

    The filler is the same length as what it replaces, so a later hit on the same
    line is still reported at its true position, and a second mention that is NOT
    owner-qualified still reaches the rules below.
    """
    for pattern in PERMITS:
        line = pattern.sub(lambda match: "." * len(match.group(0)), line)
    return line


def main(argv: list[str]) -> int:
    salt, nocase_lengths, cased_lengths, table = load()
    targets = [Path(a) for a in argv[1:]] or tracked_files()

    hits = 0
    scanned = 0
    for path in targets:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except (OSError, IsADirectoryError):
            continue  # binary, gone, or a directory: nothing to tokenize
        scanned += 1
        for number, raw_line in enumerate(text.splitlines(), start=1):
            line = permit(raw_line)
            reported: set[str] = set()
            # Two passes: case-insensitive entries are probed against the
            # lowercased line, case-sensitive ones against the line as written.
            # Folding both into one pass would make an all-caps marker match
            # ordinary lower-case prose.
            for haystack, lengths in (
                (line.lower(), nocase_lengths),
                (line, cased_lengths),
            ):
                for width in lengths:
                    for start in range(0, len(haystack) - width + 1):
                        digest = hashlib.sha256(
                            (salt + haystack[start : start + width]).encode("utf-8")
                        ).hexdigest()
                        label = table.get(digest)
                        if label is None or digest in reported:
                            continue
                        reported.add(digest)
                        hits += 1
                        # The word is never echoed. Printing it would reproduce
                        # the string into CI logs and scrollback -- committing,
                        # in the failure report, the exact leak the rule exists
                        # to prevent.
                        print(f"{path}:{number}: {label} (word withheld)")

    if hits:
        print(
            f"forbidden-word-scan: {hits} hit(s) across {scanned} file(s). "
            "This repository must stay product-neutral.",
            file=sys.stderr,
        )
        return 1
    print(f"forbidden-word-scan: {scanned} file(s) scanned, clean")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
