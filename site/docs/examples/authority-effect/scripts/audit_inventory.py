"""Bind every installed distribution to an explicit third-party audit inventory."""

import argparse
import importlib.metadata as metadata
import json
import re
from pathlib import Path

FIRST_PARTY = {
    "probity-authority-effect-cases",
    "agent-evidence-vectors",
    "probity-verify",
}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    rows = []
    for distribution in metadata.distributions():
        name = re.sub(r"[-_.]+", "-", distribution.metadata["Name"]).lower()
        rows.append(
            {
                "name": name,
                "version": distribution.version,
                "directUrl": json.loads(distribution.read_text("direct_url.json") or "{}"),
                "requiresDist": distribution.metadata.get_all("Requires-Dist") or [],
                "classification": "first_party" if name in FIRST_PARTY else "third_party",
            }
        )
    rows.sort(key=lambda row: row["name"])
    names = [row["name"] for row in rows]
    assert len(names) == len(set(names)), "duplicate installed distributions"
    assert FIRST_PARTY <= set(names), "a required owned distribution is absent"
    third_party = [row for row in rows if row["classification"] == "third_party"]
    assert third_party and all(not row["directUrl"] for row in third_party), (
        "third-party direct sources need an explicit audit identity"
    )
    for name, minimum in [("cryptography", (50,)), ("setuptools", (83,)), ("wheel", (0, 46, 2))]:
        version = next(row["version"] for row in rows if row["name"] == name)
        parts = tuple(int(part) for part in version.split("."))
        assert parts >= minimum, f"{name} is below the required dependency floor"
    (args.output / "inventory.json").write_text(json.dumps(rows, sort_keys=True, indent=2) + "\n")
    (args.output / "third-party.txt").write_text(
        "".join(f"{row['name']}=={row['version']}\n" for row in third_party)
    )
    print(json.dumps({"installed": len(rows), "thirdParty": len(third_party)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
