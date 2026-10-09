#!/usr/bin/env python3
"""A verifier under the a2a-jcs contract that canonicalizes the way a2a-python did.

``json.dumps(sort_keys=True, separators=(",", ":"))`` writes 0.000001 as
``1e-06``, escapes non-ASCII and sorts by code point, and it keeps the
``signatures`` member. The replay must fail it. It exists so the contract's
tests and the Action's end-to-end job prove a wrong canonicalizer goes red.
"""

from __future__ import annotations

import json
import sys


def main() -> int:
    with open(sys.argv[2], encoding="utf-8", errors="surrogatepass") as handle:
        try:
            value = json.loads(handle.read())
        except ValueError:
            return 1
    try:
        produced = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    except (ValueError, UnicodeEncodeError):
        return 1
    print(json.dumps({"canonical_utf8_hex": produced.hex()}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
