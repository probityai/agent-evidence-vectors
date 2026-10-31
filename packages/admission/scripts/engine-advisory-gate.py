#!/usr/bin/env python3
"""Resolve the pinned engine versions against the OSV database.

The four rails in this repository are measured with three third-party
binaries: opa, the kyverno CLI, and cue. Every one is pinned by version and
by the SHA-256 of its release asset, so a run is reproducible and the bytes
are what the pin says. Neither of those properties says the pinned version is
free of a published advisory, and nothing in the pipeline asked. A green
build with no scan is a statement about the rails, never about the engines
that ran them.

This gate reads the same version pins the workflow passes to the install
steps, resolves each against the OSV database, and fails on any advisory that
is not dispositioned in ENGINE-ADVISORIES.toml with a reason and an expiry.

Exit codes:
  0  every pinned engine resolved and nothing is outstanding.
  1  an advisory is outstanding, or a disposition has expired.
  2  the scan could not run, so nothing was checked. Never confused with 0:
     an unreachable database and a clean database are the same silence, and
     only one of them is a result.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tomllib
import urllib.error
import urllib.request
from datetime import date
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent
DISPOSITIONS = HERE / "ENGINE-ADVISORIES.toml"
OSV_QUERY = "https://api.osv.dev/v1/query"
TIMEOUT = 60

# The Go module path OSV indexes each engine under, keyed by the environment
# variable the workflow sets. The workflow env block is the single source of
# the versions; duplicating them here would let the two drift and the gate
# would then scan a version nothing installs.
ENGINES = {
    "OPA_VERSION": "github.com/open-policy-agent/opa",
    "KYVERNO_VERSION": "github.com/kyverno/kyverno",
    "CUE_VERSION": "cuelang.org/go",
}


def query(module: str, version: str) -> list[dict]:
    """Return the OSV records for one module version, or raise."""
    body = json.dumps(
        {"package": {"name": module, "ecosystem": "Go"}, "version": version}
    ).encode()
    request = urllib.request.Request(
        OSV_QUERY, data=body, headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
        return json.load(response).get("vulns", [])


def load_dispositions() -> dict[str, dict]:
    if not DISPOSITIONS.exists():
        return {}
    with DISPOSITIONS.open("rb") as handle:
        data = tomllib.load(handle)
    return {entry["id"]: entry for entry in data.get("advisory", [])}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--selftest",
        action="store_true",
        help="check the disposition file parses and every entry is complete",
    )
    args = parser.parse_args()

    try:
        dispositions = load_dispositions()
    except Exception as error:  # noqa: BLE001 - any parse failure is fatal
        print(f"engine-advisory-gate: {DISPOSITIONS.name} did not parse: {error}")
        return 2

    required = ("id", "engine", "reason", "expires")
    for identifier, entry in dispositions.items():
        missing = [field for field in required if not entry.get(field)]
        if missing:
            print(
                f"engine-advisory-gate: disposition {identifier} is missing "
                f"{', '.join(missing)}. A disposition without all four is a "
                f"suppression nobody signed."
            )
            return 2

    if args.selftest:
        print(
            f"engine-advisory-gate selftest: {len(dispositions)} disposition(s), "
            f"each carrying an id, an engine, a reason and an expiry."
        )
        return 0

    pins = {}
    for variable, module in ENGINES.items():
        raw = os.environ.get(variable)
        if not raw:
            print(
                f"engine-advisory-gate: {variable} is unset, so the version "
                f"this gate would scan is unknown and nothing was checked."
            )
            return 2
        pins[module] = raw.lstrip("v")

    today = date.today()
    outstanding: list[str] = []
    seen: set[str] = set()

    for module, version in sorted(pins.items()):
        try:
            records = query(module, version)
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as error:
            print(
                f"engine-advisory-gate: the OSV query for {module} {version} "
                f"failed ({error}). Nothing was checked."
            )
            return 2

        print(f"{module} {version}: {len(records)} record(s)")
        for record in records:
            identifier = record["id"]
            seen.add(identifier)
            summary = (record.get("summary") or "").strip()
            entry = dispositions.get(identifier)
            if entry is None:
                outstanding.append(f"  {identifier}  {module} {version}  {summary}")
                continue
            expires = entry["expires"]
            if not isinstance(expires, date):
                expires = date.fromisoformat(str(expires))
            state = "expired" if expires < today else f"held to {expires}"
            print(f"    {identifier}  dispositioned, {state}")
            if expires < today:
                outstanding.append(
                    f"  {identifier}  {module} {version}  disposition expired "
                    f"on {expires} and was not renewed"
                )

    stale = sorted(set(dispositions) - seen)
    if stale:
        print(
            "engine-advisory-gate: "
            + ", ".join(stale)
            + " no longer applies to any pinned engine. Delete the entry; a "
            "disposition that matches nothing hides the next one that would."
        )
        return 1

    if outstanding:
        print("\nengine-advisory-gate: outstanding advisories")
        print("\n".join(outstanding))
        print(
            "\nFix by bumping the pin in the workflow env block, or by adding "
            "an entry to ENGINE-ADVISORIES.toml carrying the identifier, the "
            "engine, why this repository is out of reach of it, and the date "
            "the reason is to be re-read."
        )
        return 1

    print(
        f"\nengine-advisory-gate: {len(pins)} pinned engine(s) resolved, "
        f"{len(dispositions)} dispositioned advisory(s), none outstanding."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
