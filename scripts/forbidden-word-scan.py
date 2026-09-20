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

# A sibling module in this directory, resolved from this file rather than from
# the caller's path, the same way scripts/forcing-gate.py reaches
# scripts/_lockfile.py. The sidecar loader below is still copied rather than
# imported, for the reason its own comment gives.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from _decoding import GUARD_MATERIAL, GUARD_SPANS, views  # noqa: E402

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



# The organisation that owns this repository is named in its own URLs, and a URL
# cannot avoid naming its owner. The permit is a PATH permit and not a word
# permit: the handle passes only where a slash and one of this family's three
# repository names follow it. Everything else stays refused, including the handle
# alone. Copied verbatim from scripts/pre-push-identity-scan.py, not imported, for
# the reason that file gives: these guards must run with no import path to break.
OWNER_SPAN = "70726f626974796169"
PERMITTED_PATH = re.compile(
    bytes.fromhex(OWNER_SPAN).decode("ascii")
    + r"(?:\.github\.io)?/(?:agent-evidence-(?:vectors|vocabulary|admission)|jcs-admit|dsse)\b",
    re.IGNORECASE,
)

# Rule material is exempt from the decoding step for the reason
# `_decoding.material` gives: a guard that holds a term cannot hold it in a
# decodable form and also decode everything. This scan reads every tracked file,
# so the material it meets is not only its own -- the sibling history scanner's
# word list is a file in this tree -- which is why the declared set is shared.
if OWNER_SPAN not in GUARD_SPANS:
    print(
        "forbidden-word-scan: this file's rule span is not declared in "
        "_decoding.GUARD_SPANS; add it there so every guard exempts it alike",
        file=sys.stderr,
    )
    raise SystemExit(2)


def permit(line: str) -> str:
    """Blank owner-qualified repository paths, preserving every offset.

    Same-length filler, so a window that starts inside the masked span can no
    longer hash to a rule, and a second mention on the same line that is not
    owner-qualified still reaches both passes below.
    """
    return PERMITTED_PATH.sub(lambda m: "." * len(m.group(0)), line)


def labels(
    line: str, salt: str, nocase_lengths: list[int], cased_lengths: list[int], table: dict[str, str]
) -> list[str]:
    """Every sidecar label whose word occurs in `line`, each reported once.

    Two passes: case-insensitive entries are probed against the lowercased line,
    case-sensitive ones against the line as written. Folding both into one pass
    would make an all-caps marker match ordinary lower-case prose.
    """
    found: list[str] = []
    reported: set[str] = set()
    for haystack, lengths in ((line.lower(), nocase_lengths), (line, cased_lengths)):
        for width in lengths:
            for start in range(0, len(haystack) - width + 1):
                digest = hashlib.sha256(
                    (salt + haystack[start : start + width]).encode("utf-8")
                ).hexdigest()
                label = table.get(digest)
                if label is None or digest in reported:
                    continue
                reported.add(digest)
                found.append(label)
    return found


def readings(line: str) -> list[tuple[str, str]]:
    """One line as (where it sits, text to match), raw first and then decoded.

    A forbidden word inside a base64 payload is in this repository's tracked
    CONTENT exactly as much as one in its prose, and this scan used to read past
    it: signed statements carry their payload encoded, and signed statements are
    what this repository publishes. `_decoding.views` decodes base64 in both
    alphabets padded or not, hex and percent-encoding, and follows nesting, so
    the sidecar words are probed against every layer. The layers crossed are
    printed with the finding; the word never is.
    """
    decoded = views(line, GUARD_MATERIAL)
    return [("", line), *((f" [{layers}]", permit(text)) for layers, text in decoded)]


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
            for where, reading in readings(permit(raw_line)):
                for label in labels(reading, salt, nocase_lengths, cased_lengths, table):
                    hits += 1
                    # The word is never echoed. Printing it would reproduce the
                    # string into CI logs and scrollback -- committing, in the
                    # failure report, the exact leak the rule exists to prevent.
                    print(f"{path}:{number}{where}: {label} (word withheld)")

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
