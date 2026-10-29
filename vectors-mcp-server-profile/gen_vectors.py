#!/usr/bin/env python3
"""Regenerate the MCP server profile corpus byte-identically.

    python3 gen_vectors.py            # write records/, MANIFEST.json, INDEX.md
    python3 gen_vectors.py --check    # refuse when the tree on disk differs

The subject is a **server run record**: what a recorder saw when it launched one
version of one MCP server. Six conditions cover the tool-description digest pin,
the rug-pull diff against the previous version, the egress record, the rule that a
missing observation is never clean, and the binding of the record to an artifact
digest. A seventh covers the run set: a headline over many servers keeps every
server that crashed or failed to start in its denominator.

Every member is synthetic. Tool digests are derived from fixed strings, so a
regeneration is byte-identical. Each reject member differs from its accepting
twin in exactly one observed or reported field and violates exactly one
condition, so a checker that refuses everything scores zero.

`check_server_record.py` is the criterion as code and is the corpus's own oracle.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import check_server_record as criterion  # noqa: E402

SUITE = "mcp-server-profile"
TRACKS_UPSTREAM = "modelcontextprotocol/registry"


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def tool_digest(name: str, revision: int) -> str:
    return "sha256:" + sha(f"tool:{name}:r{revision}".encode())


ARTIFACT = "sha256:" + sha(b"artifact:server-one:1.1.0")

CONDITIONS: dict[str, dict[str, str]] = {
    "msp-c-1": {
        "requires": "The record lists every served tool whose definition digest differs from its approved pin, and every served tool that has no pin.",
        "why": "a tool-description change after approval is the rug pull, and a record that omits it reads as a clean run",
    },
    "msp-c-2": {
        "requires": "The record's version diff lists exactly the tools changed, added and removed against the previous version's digests.",
        "why": "a reviewer approving an update reads the diff, so an omitted tool is a change nobody was shown",
    },
    "msp-c-3": {
        "requires": "Every host the server contacted that its declared egress does not name is listed as undeclared.",
        "why": "the egress record is the only part of the run that shows where data left, and an unlisted host is the one that mattered",
    },
    "msp-c-4": {
        "requires": "A run whose egress was not recorded ends as couldnt-run, never as clean or flagged.",
        "why": "a missing observation read as an empty one is how a server that crashed on start gets a clean badge",
    },
    "msp-c-5": {
        "requires": "A clean outcome requires no pin mismatch and no undeclared host once both are recomputed from the observed fields.",
        "why": "the outcome is the field a registry ingests, so it must follow from the observations beside it",
    },
    "msp-c-6": {
        "requires": "The record binds the artifact it ran by a sha256 digest, not by a version string.",
        "why": "a version string is a name its owner can re-point, so a record naming one describes whatever the name resolves to later",
    },
    "msp-c-7": {
        "requires": "A run set's results add up to the servers attempted, and its headline denominator is the servers attempted.",
        "why": "a server that crashed is still a server the registry asked about, and a headline over the survivors turns a failure rate into a pass rate",
    },
}


def tools(names: dict[str, int]) -> dict[str, str]:
    return {name: tool_digest(name, rev) for name, rev in names.items()}


def run_record(
    *,
    served_rev: dict[str, int],
    pinned_rev: dict[str, int] | None = None,
    previous_rev: dict[str, int] | None = None,
    declared: list[str] | None = None,
    observed: list[str] | None = None,
    observation: str = "recorded",
    outcome: str = "clean",
    artifact: str = ARTIFACT,
    version: str = "1.1.0",
) -> dict:
    """Build a record whose reported fields are the true recomputation."""
    served = tools(served_rev)
    pinned = tools(pinned_rev if pinned_rev is not None else served_rev)
    previous = tools(previous_rev if previous_rev is not None else served_rev)
    record = {
        "recordType": "server-run",
        "server": {"name": "server-one", "version": version, "artifactDigest": artifact},
        "declaredEgress": declared if declared is not None else ["api.example.com"],
        "tools": {"pinned": pinned, "served": served, "mismatchReported": []},
        "diff": {"previousVersion": "1.0.0", "previousTools": previous, "reported": {}},
        "egress": {
            "observation": observation,
            "observed": observed if observed is not None else ["api.example.com"],
            "undeclaredReported": [],
        },
        "outcome": outcome,
    }
    record["tools"]["mismatchReported"] = criterion.pin_mismatches(record["tools"])
    record["diff"]["reported"] = criterion.version_diff(record["diff"], served)
    record["egress"]["undeclaredReported"] = criterion.undeclared_hosts(record)
    return record


def run_set(*, attempted: int, clean: int, flagged: int, couldnt: int, denominator: int) -> dict:
    return {
        "recordType": "run-set",
        "listDigest": "sha256:" + sha(b"pinned-list:v1"),
        "attempted": attempted,
        "results": {"clean": clean, "flagged": flagged, "couldntRun": couldnt},
        "headlineDenominator": denominator,
    }


def build() -> list[dict]:
    members: list[dict] = []

    def add(kind: str, condition: str, payload: dict, cites: str) -> None:
        violated = criterion.check(payload)
        want = [condition] if kind == "reject" else []
        if violated != want:
            raise SystemExit(f"FAIL: {condition} {kind} member violates {violated}, wanted {want}")
        members.append(
            {
                "kind": kind,
                "conditions": [condition],
                "payload": payload,
                "expected": {"violates": violated},
                "cites": cites,
            }
        )

    base = {"read_file": 1, "list_dir": 1}

    # msp-c-1: the digest pin ------------------------------------------------
    pinned_hit = run_record(served_rev={"read_file": 2, "list_dir": 1}, pinned_rev=base, outcome="flagged")
    add("accept", "msp-c-1", pinned_hit, "a served tool whose description changed after approval is listed and the run is flagged")
    hidden = copy.deepcopy(pinned_hit)
    hidden["tools"]["mismatchReported"] = []
    add("reject", "msp-c-1", hidden, "the same changed tool, absent from the mismatch list although the outcome is flagged")
    unpinned = run_record(served_rev={"read_file": 1, "list_dir": 1, "write_file": 1}, pinned_rev=base, previous_rev=base, outcome="flagged")
    add("accept", "msp-c-1", unpinned, "a served tool that was never approved is listed as a mismatch")
    silent_new = copy.deepcopy(unpinned)
    silent_new["tools"]["mismatchReported"] = []
    add("reject", "msp-c-1", silent_new, "a served tool with no pin, absent from the mismatch list")

    # msp-c-2: the rug-pull diff --------------------------------------------
    changed = run_record(served_rev={"read_file": 2, "list_dir": 1}, previous_rev=base)
    add("accept", "msp-c-2", changed, "the update changed one tool and the diff lists it; the pins were refreshed so the run is clean")
    omitted = copy.deepcopy(changed)
    omitted["diff"]["reported"]["changed"] = []
    add("reject", "msp-c-2", omitted, "the update changed a tool and the diff reports no change")
    grown = run_record(served_rev={"read_file": 1, "list_dir": 1, "write_file": 1}, previous_rev=base)
    add("accept", "msp-c-2", grown, "the update added a tool and the diff lists it as added")
    omitted_add = copy.deepcopy(grown)
    omitted_add["diff"]["reported"]["added"] = []
    add("reject", "msp-c-2", omitted_add, "the update added a tool and the diff does not list it")

    # msp-c-3: the egress record --------------------------------------------
    leak = run_record(served_rev=base, observed=["api.example.com", "collect.example.net"], outcome="flagged")
    add("accept", "msp-c-3", leak, "the server contacted a host its declaration does not name and the record lists it")
    unlisted = copy.deepcopy(leak)
    unlisted["egress"]["undeclaredReported"] = []
    add("reject", "msp-c-3", unlisted, "the same contact, absent from the undeclared list")

    # msp-c-4: a missing observation is not clean ---------------------------
    crashed = run_record(served_rev=base, observation="not-run", observed=[], outcome="couldnt-run")
    add("accept", "msp-c-4", crashed, "the server crashed on start, nothing was observed, and the outcome says so")
    faked = copy.deepcopy(crashed)
    faked["outcome"] = "clean"
    add("reject", "msp-c-4", faked, "the same crashed run recorded as clean")

    # msp-c-5: the outcome follows the observations -------------------------
    clean = run_record(served_rev=base)
    add("accept", "msp-c-5", clean, "no mismatch and no undeclared host, so clean follows")
    inflated = run_record(served_rev={"read_file": 2, "list_dir": 1}, pinned_rev=base, outcome="clean")
    add("reject", "msp-c-5", inflated, "a pin mismatch correctly listed, and an outcome of clean beside it")

    # msp-c-6: artifact binding ---------------------------------------------
    named = run_record(served_rev=base, artifact="1.1.0")
    add("reject", "msp-c-6", named, "the artifact is named by a version string")
    add("accept", "msp-c-6", run_record(served_rev=base, version="1.1.0"), "the artifact is bound by its sha256 digest")

    # msp-c-7: the run set denominator --------------------------------------
    honest = run_set(attempted=20, clean=11, flagged=4, couldnt=5, denominator=20)
    add("accept", "msp-c-7", honest, "twenty attempted, five that could not run counted, denominator twenty")
    add("reject", "msp-c-7", run_set(attempted=20, clean=11, flagged=4, couldnt=4, denominator=20), "the results add up to nineteen of twenty attempted: one server dropped")
    add("reject", "msp-c-7", run_set(attempted=20, clean=11, flagged=4, couldnt=5, denominator=15), "the headline denominator is fifteen: the servers that could not run were left out")

    return members


def identify(member: dict) -> str:
    payload = json.dumps(
        {"kind": member["kind"], "conditions": member["conditions"], "payload": member["payload"]},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return "v" + sha(payload)[:16]


def render_index(manifest: dict) -> str:
    rows = "\n".join(
        "| `{id}` | {kind} | {cond} | {violates} |".format(
            id=e["id"],
            kind=e["kind"],
            cond=", ".join(e["conditions"]),
            violates=", ".join(e["expected"]["violates"]) or "nothing",
        )
        for e in manifest["vectors"]
    )
    conditions = "\n".join(
        "| `{k}` | {requires} Because {why}. |".format(k=k, requires=v["requires"], why=v["why"])
        for k, v in sorted(CONDITIONS.items())
    )
    total = len(manifest["vectors"])
    accept, reject = manifest["counts"]["accept"], manifest["counts"]["reject"]
    return f"""# Conformance vectors (MCP server profile)

Every member of this suite in one table. The subject under test is a **server
run record**: what a recorder saw when it launched one version of one MCP
server, and the verdict it drew.

This corpus is {total} vectors, of which {accept} a conformant verifier must
not fail closed on and {reject} it must reject.

Every member is synthetic and names no server or party. A reject member differs
from its accepting twin in one observed or reported field and violates exactly
one condition.

Regenerate byte-identically: `python3 gen_vectors.py`.
Self-check: `aee-verify vectors-mcp-server-profile/` from the repository root.
Check a record: `python3 check_server_record.py records/<id>.json`.

## Conditions

| id | what it requires |
|---|---|
{conditions}

## Vectors

| id | kind | condition | conditions the checker finds broken |
|---|---|---|---|
{rows}
"""


def build_manifest() -> tuple[dict, dict[str, bytes]]:
    members = build()
    seen: set[str] = set()
    files: dict[str, bytes] = {}
    entries = []
    for member in members:
        vid = identify(member)
        if vid in seen:
            raise SystemExit(f"FAIL: duplicate identifier {vid}")
        seen.add(vid)
        rel = f"records/{vid}.json"
        files[rel] = json.dumps(member["payload"], indent=2, sort_keys=True).encode("utf-8") + b"\n"
        entries.append(
            {
                "id": vid,
                "kind": member["kind"],
                "record": rel,
                "conditions": member["conditions"],
                "expected": member["expected"],
                "cites": member["cites"],
            }
        )
    entries.sort(key=lambda e: e["id"])
    counts = {k: sum(1 for e in entries if e["kind"] == k) for k in ("accept", "reject")}
    manifest = {
        "suite": SUITE,
        "subject": "an MCP server run record",
        "tracksUpstream": TRACKS_UPSTREAM,
        "checker": "check_server_record.py",
        "conditions": CONDITIONS,
        "counts": counts,
        "corpusDigest": sha(b"".join(files[e["record"]] for e in entries)),
        "note": (
            "Every member is synthetic. A reject member violates one declared "
            "condition and differs from an accepting twin in one field, so a "
            "checker that refuses everything scores zero rather than full marks."
        ),
        "vectors": entries,
    }
    files["MANIFEST.json"] = json.dumps(manifest, indent=2).encode("utf-8") + b"\n"
    files["INDEX.md"] = render_index(manifest).encode("utf-8")
    return manifest, files


def verify_tree(files: dict[str, bytes]) -> int:
    bad = []
    for rel, payload in sorted(files.items()):
        path = os.path.join(HERE, rel)
        if not os.path.exists(path):
            bad.append(f"{rel} is missing")
            continue
        with open(path, "rb") as handle:
            if handle.read() != payload:
                bad.append(f"{rel} differs from what the generator emits")
    root = os.path.join(HERE, "records")
    if os.path.isdir(root):
        for name in sorted(os.listdir(root)):
            if f"records/{name}" not in files:
                bad.append(f"records/{name} is on disk and the generator emits no such file")
    if bad:
        for line in bad:
            print("FAIL", line, file=sys.stderr)
        print("\nRun `python3 gen_vectors.py` to rebuild, and commit the diff.", file=sys.stderr)
        return 1
    print(f"OK generator reproduces {len(files)} file(s) byte-identically")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="refuse a tree this does not emit")
    check = parser.parse_args().check
    manifest, files = build_manifest()
    if check:
        return verify_tree(files)
    os.makedirs(os.path.join(HERE, "records"), exist_ok=True)
    for name in sorted(os.listdir(os.path.join(HERE, "records"))):
        if f"records/{name}" not in files:
            os.unlink(os.path.join(HERE, "records", name))
    for rel, payload in sorted(files.items()):
        with open(os.path.join(HERE, rel), "wb") as handle:
            handle.write(payload)
    counts = manifest["counts"]
    print(f"wrote {len(files)} file(s): {counts['accept']} accept, {counts['reject']} reject, corpus {manifest['corpusDigest'][:12]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
