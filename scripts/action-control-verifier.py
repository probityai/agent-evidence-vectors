#!/usr/bin/env python3
"""A verifier that answers every member the same way: the action's null controls.

    python3 -S action-control-verifier.py accept <vector-file>
    python3 -S action-control-verifier.py reject <vector-file>
    python3 -S action-control-verifier.py accept <target> <input.json>   # a2a-jcs contract

The action replays the corpus through this program twice, once as an
always-accept verifier and once as an always-reject one, and prints what each
scored beside the verifier under test. A corpus where a constant answer passes
more members than must be accepted (or rejected) cannot tell a verifier from a
constant, and a green run on it says less than it looks.

Under the generic contract (docs/reference/verifier-contract.md) accept is exit
0 with `{"verdict": "valid"}` and reject is exit 1 with `{"verdict":
"invalid", "codes": []}`. Under the a2a canonicalization contract
(docs/reference/corpus-readers.md) accept answers the input's own bytes as its
canonical form, which is the identity canonicalizer, and reject refuses with
exit 1. No other answer is attempted: a control that tried to be right would
stop being a control. Standard library only.
"""

from __future__ import annotations

import json
import sys


def main(argv: list[str]) -> int:
    if len(argv) < 2 or argv[0] not in ("accept", "reject"):
        print("usage: action-control-verifier.py accept|reject <vector-file> | <target> <input>",
              file=sys.stderr)
        return 2
    mode, rest = argv[0], argv[1:]
    if len(rest) == 2:
        # The a2a-jcs contract: <target> <input.json>.
        if mode == "reject":
            return 1
        with open(rest[1], "rb") as handle:
            raw = handle.read().rstrip(b"\r\n")
        print(json.dumps({"canonical_utf8_hex": raw.hex()}))
        return 0
    if mode == "accept":
        print(json.dumps({"verdict": "valid"}))
        return 0
    print(json.dumps({"verdict": "invalid", "codes": []}))
    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
