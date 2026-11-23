"""Fixture verifier: a case is valid when it is a JSON object whose `ok` is true."""

import json
import sys

try:
    with open(sys.argv[1], encoding="utf-8") as handle:
        case = json.load(handle)
except (OSError, ValueError):
    case = None
valid = isinstance(case, dict) and case.get("ok") is True
print(json.dumps({"verdict": "valid" if valid else "invalid"}))
sys.exit(0 if valid else 1)
