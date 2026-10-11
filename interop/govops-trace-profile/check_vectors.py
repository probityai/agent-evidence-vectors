"""Judge the committed GovOps TRACE corpus and prove every rule is load-bearing.

Exit 0 only when every member file matches the digest MANIFEST.json records for
it; when the reference reader reaches each member's expected verdict, code and
flags; when the capability resolutions the funds transfer depends on equal the
values written below by hand, so they are not the reader's own output read back;
and when turning off any single rule changes the result of every member that
names it. A rule no member depends on, or a member that passes without its rule,
fails the sweep.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from verifier import RULES, judge  # noqa: E402

FUNDS = [{"capability_ids": ["invoke:funds-transfer"], "resolution_status": "resolved"}]
HAND = {
    "GT-A1": {"dec-0040": FUNDS, "dec-0041": FUNDS, "inv-0090": FUNDS, "inv-0091": FUNDS},
    "GT-F1": {"dec-0040": FUNDS, "dec-0041": FUNDS},
    "GT-F6": {"inv-0090": [{"capability_ids": [], "resolution_status": "unmapped"}]},
    "GT-A3": {
        "dec-0040": FUNDS,
        "dec-0041": [
            {
                "decision_id": "d1",
                "capability_ids": ["invoke:funds-transfer"],
                "resolution_status": "resolved",
            },
            {
                "decision_id": "d2",
                "capability_ids": ["read:account-balance"],
                "resolution_status": "resolved",
            },
        ],
    },
}
HAND["GT-A2"] = HAND["GT-A1"]


def _compare(entry: dict[str, Any], got: dict[str, Any]) -> list[str]:
    mid = entry["id"]
    out = []
    if got["verdict"] != entry["verdict"]:
        out.append(f"{mid}: verdict {got['verdict']} != {entry['verdict']} ({got})")
    if entry["verdict"] == "reject" and got.get("code") != entry["code"]:
        out.append(f"{mid}: code {got.get('code')} != {entry['code']}")
    if entry["verdict"] != "reject" and got.get("flags") != entry["flags"]:
        out.append(f"{mid}: flags {got.get('flags')} != {entry['flags']}")
    res = got.get("capability_resolution", {})
    for rid, want in HAND.get(mid, {}).items():
        if res.get(rid) != want:
            out.append(f"{mid}: resolution of {rid} {res.get(rid)} != {want}")
    return out


def _sweep(
    manifest: dict[str, Any], loaded: dict[str, Any], reg: dict[str, Any], mp: dict[str, Any]
) -> tuple[int, list[str]]:
    out = []
    used = 0
    for rule in RULES:
        named = [e for e in manifest["members"] if e["code"] == rule or rule in e["flags"]]
        if not named:
            out.append(f"sweep: no member exercises rule {rule}")
            continue
        used += 1
        for e in named:
            if judge(loaded[e["id"]], reg, mp) == judge(
                loaded[e["id"]], reg, mp, frozenset({rule})
            ):
                out.append(f"sweep: {e['id']} is unchanged with rule {rule} off")
    return used, out


def main() -> int:
    manifest = json.loads((HERE / "MANIFEST.json").read_text())
    ctx = (
        json.loads((HERE / "registry.json").read_text()),
        json.loads((HERE / "mapping.json").read_text()),
    )
    failures: list[str] = []
    loaded = {}
    for entry in manifest["members"]:
        raw = (HERE / "members" / f"{entry['id']}.json").read_bytes()
        if hashlib.sha256(raw).hexdigest() != entry["sha256"]:
            failures.append(f"{entry['id']}: file digest differs from MANIFEST.json")
        loaded[entry["id"]] = json.loads(raw)
        failures += _compare(entry, judge(loaded[entry["id"]], *ctx))
    used, swept = _sweep(manifest, loaded, *ctx)
    failures += swept
    for f in failures:
        print(f)
    print(
        f"{len(manifest['members'])} members, {used} of {len(RULES)} rules swept, "
        f"{len(failures)} failures"
    )
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
