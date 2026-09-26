#!/usr/bin/env python3
"""Generate the salted-hash sidecar that the commit-msg hook and the CI scan read.

The plaintext word list is an INPUT to this script and must never be committed
to this repository. Keep it wherever the words already live -- a private repo,
a password manager, a file under `~` -- and pass its path here.

    scripts/gen-forbidden-tokens.py --label 'first-party product name' \\
        ~/private/forbidden-words.txt > .githooks/commit-msg.forbidden-words

One word per line; blank lines and `#` comments are ignored. Each word is lowercased and must
contain no whitespace: readers slide a fixed-width window over a lowercased
line, so a word with a space in it could never be produced by any window and
would be a rule that can never fire. That is refused here, never shipped
as a silent no-op.

Re-running with the same salt is deterministic, so regenerating after adding a
word produces a clean one-line diff.
"""

from __future__ import annotations

import argparse
import hashlib
import re
import secrets
import sys
from pathlib import Path

WORD = re.compile(r"[^\n]+\Z")


def read_wordlist(path: Path, default_label: str) -> list[tuple[str, str, str]]:
    """Read the private list into `(word, case_flag, label)` triples, or refuse.

    An entry no window could ever produce is refused here, never shipped
    as a rule that silently never fires.
    """
    words: list[tuple[str, str, str]] = []
    lines = path.read_text(encoding="utf-8").splitlines()
    for number, raw in enumerate(lines, start=1):
        entry = raw.rstrip("\n")
        if not entry.strip() or entry.lstrip().startswith("#"):
            continue
        # An optional per-entry case flag and label, so one private list can
        # cover several rule kinds and the public sidecar stays a single file.
        line, _, rest = entry.partition("\t")
        flag, _, label = rest.partition("\t")
        flag = (flag.strip() or "i").lower()
        if flag not in ("i", "s"):
            raise ValueError(f"{path}:{number}: case flag must be 'i' or 's'")
        line = line.strip()
        if not WORD.match(line):
            raise ValueError(
                f"{path}:{number}: {line!r} is empty or spans a line break, so no "
                "window could ever produce it and the rule could never fire"
            )
        # 'i' entries are hashed lowercased and probed against a lowercased
        # window; 's' entries are hashed as written and probed against the raw
        # window. A product name must match in any casing; an all-caps marker
        # must not, because lower-cased it is ordinary English.
        words.append(
            (line.lower() if flag == "i" else line, flag, label.strip() or default_label)
        )
    return words


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("wordlist", type=Path, help="path to the private word list")
    parser.add_argument(
        "--salt",
        default=None,
        help="hex salt to reuse; omit to mint a new one (changes every digest)",
    )
    parser.add_argument(
        "--label",
        default="first-party product name in a public, product-neutral repository",
        help="label reported when a word is caught",
    )
    args = parser.parse_args(argv[1:])

    salt = args.salt or secrets.token_hex(16)
    if not re.fullmatch(r"[0-9a-f]{16,}", salt):
        print("salt must be at least 16 lowercase hex characters", file=sys.stderr)
        return 2

    try:
        words = read_wordlist(args.wordlist, args.label)
    except ValueError as exc:
        print(exc, file=sys.stderr)
        return 2

    if not words:
        print(f"{args.wordlist}: no words found", file=sys.stderr)
        return 2

    print("# Salted digests of the words this repository must never contain.")
    print("#")
    print("# There is no plaintext here on purpose. A rule that spells out what it")
    print("# forbids publishes the string it exists to suppress, and a rule written")
    print("# to exempt its own file leaves the one file nobody scans as the one file")
    print("# that names them. Regenerate with scripts/gen-forbidden-tokens.py from")
    print("# the private word list; reuse --salt to keep the diff to one line.")
    print("#")
    print("# Readers lowercase each line and slide a window of every declared")
    print("# length across it, looking up sha256(salt + window). That reproduces a")
    print("# case-insensitive substring search exactly, so a word glued inside a")
    print("# longer identifier is still caught. The lengths must be declared for")
    print("# the window to exist; leaking a word length is far less than the word.")
    print("#")
    print("# This is obscurity, not secrecy: the candidate space is small")
    print("# enough to brute-force -- and it is sized to the actual threat: a")
    print("# careless paste, a search engine, and a casual reader.")
    print(f"# salt: {salt}")
    for flag, header in (("i", "lengths-i"), ("s", "lengths-s")):
        widths = sorted({len(w) for w, f, _ in set(words) if f == flag})
        if widths:
            print(f"# {header}: {','.join(str(n) for n in widths)}")
    for word, _flag, label in sorted(set(words)):
        digest = hashlib.sha256((salt + word).encode("utf-8")).hexdigest()
        print(f"{digest}\t{label}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
