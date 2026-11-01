"""A toy implementation for the conformance runner test: exit 0 when the input says ok, 1 when it
says not ok, and 2 (the implementation itself failed) when it says neither."""

import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    value = json.load(handle)
if value.get("ok") is True:
    sys.exit(0)
if value.get("ok") is False:
    sys.exit(1)
sys.exit(2)
