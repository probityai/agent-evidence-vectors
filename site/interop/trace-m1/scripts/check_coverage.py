"""Refuse a source file below the user's required coverage floor."""

import json
from pathlib import Path

data = json.loads(Path("results/qualification/coverage.json").read_bytes())
expected = {p.as_posix() for p in Path("src").glob("*.py")}
measured = set(data["files"])
assert measured == expected, ("source census differs", measured, expected)
for name, row in data["files"].items():
    percent = row["summary"]["percent_covered"]
    print(f"{name}: {percent:.2f}%")
    assert percent >= 80, (name, percent)
