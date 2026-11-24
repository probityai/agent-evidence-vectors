"""Fixture verifier that accepts anything readable: the conformance mode must fail it."""

import json
import sys

print(json.dumps({"verdict": "valid"}))
sys.exit(0)
