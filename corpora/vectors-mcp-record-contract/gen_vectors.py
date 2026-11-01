#!/usr/bin/env python3
"""Regenerate the run-record contract corpus byte-identically.

    python3 gen_vectors.py            # write records/, MANIFEST.json, INDEX.md
    python3 gen_vectors.py --check    # refuse when the tree on disk differs

The subject of this corpus is not a protocol message. It is a **run record**:
the artifact a cross-implementation claim rests on. A claim of the shape "our
two implementations agree, N of N" is evidence when a third party can obtain
the same result from what is published and compare it byte for byte, and is an
assertion otherwise. The two are indistinguishable in a table, which is what
the corpus is for.

Every member here is synthetic. Each is shaped after a defect observed in
published cross-run claims in open specification threads, and none transcribes
or attributes a particular claim: the shape is the thing under test, and a
corpus that named parties would be an accusation with a schema.

`check_run_record.py` is the criterion as code. This corpus is that checker's
own conformance suite, so the criterion is measured rather than asserted.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))

SUITE = "cross-run-record-contract"
TRACKS_UPSTREAM = "modelcontextprotocol/modelcontextprotocol#3004"
CRITERION = "docs/INTEROP-EVIDENCE.md"

#: A digest and a full commit identifier, used throughout so that a member's
#: defect is the only thing that varies between it and its twin.
REF_A = "529515ba7445af0f07e5da578ad938e371e8c7a8"
REF_B = "4b9dbb006642f2c47800f62412db3a4b6a1b42e4"
RUNNER_A = "139c78af873f4991981d0be0a07062b84dad7d65"
RUNNER_B = "43b6eba31b3caffe09f71a20cbd3f944c8786799"
OUT_A = "sha256:" + "a" * 64
OUT_B = "sha256:" + "b" * 64

CONDITIONS: dict[str, dict[str, str]] = {
    "mrc-c-1": {
        "requires": (
            "The inputs carry an immutable reference. A repository name and a "
            "version string name a thing that can change under the claim."
        ),
        "why": (
            "one project in this area published a tag against the wrong commit "
            "and left it in place rather than moving it, which is the honest "
            "response and also the proof that a tag can be moved"
        ),
    },
    "mrc-c-2": {
        "requires": (
            "The runner carries an immutable reference or a digest. Naming the "
            "library it was built on is not naming the runner."
        ),
        "why": (
            "the driver that loads the inputs and emits the result is the part a "
            "third party has to have, and it is the part most often absent while "
            "both endpoints resolve"
        ),
    },
    "mrc-c-3": {
        "requires": "The invocation is published verbatim.",
        "why": (
            "a reader who has the inputs and the runner and not the invocation "
            "knows what ran and not what was asked of it"
        ),
    },
    "mrc-c-4": {
        "requires": (
            "The result is published and carries a digest. A digest over a file "
            "nobody else can hold is a claim rather than a comparison."
        ),
        "why": (
            "the digest is what turns a re-run into a comparison; without the "
            "file the digest is a promise, and without the digest the file is an "
            "unpinned artifact"
        ),
    },
    "mrc-c-5": {
        "requires": (
            "A figure states its counting rule: what the denominator counts, and "
            "how a member that was not scored is counted."
        ),
        "why": (
            "a figure written as N of N is read as N passes, and the same run is "
            "honestly describable as N members with no failures when some were "
            "deliberately not scored; those are different claims and only one of "
            "them is what a reader takes away"
        ),
    },
    "mrc-c-6": {
        "requires": (
            "Independence is declared: whether the party that ran the inputs "
            "authored them."
        ),
        "why": (
            "a self-report is worth publishing and is not independent evidence, "
            "and a reader cannot infer which one a record is"
        ),
    },
}


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
def corpus_digest(manifest: dict, root: str = str(HERE)) -> str:
    """The digest this corpus publishes, recomputed from the files on disk.

    It lives with the GENERATOR because the generator owns the preimage. Its
    one caller besides this file is scripts/release-digests.py, which loads it
    by path rather than restating the concatenation: a second spelling of one
    preimage drifts from the first, and a release signature over a drifted
    digest certifies the drift instead of the corpus.
    """
    return sha(b"".join(
        open(os.path.join(root, entry["record"]), "rb").read()
        for entry in manifest["vectors"]))



def side(
    label: str,
    *,
    inputs_ref: str | None = REF_A,
    inputs_name: str = "a published vector set",
    runner_ref: str | None = RUNNER_A,
    runner_digest: str | None = None,
    runner_name: str = "a from-scratch verifier",
    invocation: str | None = "VECTORS_DIR=./vectors OUT_DIR=. verify --all",
    output_digest: str | None = OUT_A,
    published: bool = True,
    environment: str | None = "node 24.19.0, linux",
) -> dict:
    out: dict = {
        "label": label,
        "inputs": {"name": inputs_name},
        "runner": {"name": runner_name},
        "invocation": invocation,
        "output": {"path": "results.json", "published": published},
    }
    if inputs_ref is not None:
        out["inputs"]["ref"] = inputs_ref
    if runner_ref is not None:
        out["runner"]["ref"] = runner_ref
    if runner_digest is not None:
        out["runner"]["digest"] = runner_digest
    if output_digest is not None:
        out["output"]["digest"] = output_digest
    if environment is not None:
        out["environment"] = environment
    return out


def record(
    *,
    sides: list[dict],
    figure: dict | None = None,
    independence: dict | None = None,
    ran_at: str = "2026-07-20T17:56:38Z",
) -> dict:
    out: dict = {
        "recordVersion": "1",
        "claim": "two implementations agree on a shared vector set",
        "ranAt": ran_at,
        "sides": sides,
    }
    if figure is not None:
        out["figure"] = figure
    if independence is not None:
        out["independence"] = independence
    return out


def headline(scored: int, total: int) -> str:
    """The figure a record puts at the top, built rather than typed.

    Constructed from the two counts so that a fixture's headline cannot drift
    from the counts beneath it through a typo. The point of the misleading
    members is that the headline and the counts disagree by DESIGN, and a
    disagreement introduced by accident would be indistinguishable from one
    introduced on purpose.
    """
    return f"{scored} of {total}" if scored != total else f"{total} of {total}"


def whole_figure(total: int) -> dict:
    return {
        "headline": headline(total, total),
        "total": total,
        "scored": total,
        "notScored": [],
        "countingRule": (
            f"the denominator counts the {total} members of the vector set at the "
            "pinned reference; every member was scored and every scored member "
            "agreed"
        ),
    }


def member_expectation(kind: str, condition: str, stance: str) -> dict:
    """What the checker must answer for a member, on all three axes.

    A reject member fails exactly one axis, named by its condition. Writing the
    expectation as three answers rather than one pass or fail is what keeps a
    member that is re-checkable and carries a misleading figure from being
    scored the same as one nobody can re-run. Independence is a three-valued
    fact rather than a pass, because a declared self-report is worth publishing
    and only an undeclared one leaves a reader guessing.
    """
    return {
        "recheckable": not (kind == "reject" and condition in FOUR_INPUTS),
        "figureMeansWhatItSays": not (kind == "reject" and condition == "mrc-c-5"),
        "independence": stance,
    }


#: The four conditions a re-run needs. A member failing one of these is not
#: re-checkable; a member failing either of the other two is re-checkable and
#: means something other than it appears to.
FOUR_INPUTS = frozenset({"mrc-c-1", "mrc-c-2", "mrc-c-3", "mrc-c-4"})


def build() -> list[dict]:
    members: list[dict] = []

    def add(*, kind: str, condition: str, payload: dict, cites: str) -> None:
        declared = payload.get("independence") or {}
        if not declared.get("declared"):
            stance = "undeclared"
        elif declared.get("runnerAuthoredInputs"):
            stance = "self-report"
        else:
            stance = "independent"
        members.append(
            {
                "kind": kind,
                "conditions": [condition],
                "payload": payload,
                "expected": member_expectation(kind, condition, stance),
                "cites": cites,
            }
        )

    independent = {"declared": True, "runnerAuthoredInputs": False}
    self_report = {"declared": True, "runnerAuthoredInputs": True}

    # The reference member: everything present, both directions.
    both = [
        side("forward"),
        side("reverse", inputs_ref=REF_B, runner_ref=RUNNER_B, output_digest=OUT_B),
    ]
    add(
        kind="accept",
        condition="mrc-c-1",
        payload=record(sides=copy.deepcopy(both), figure=whole_figure(6), independence=independent),
        cites=(
            "the record a re-checkable cross-run produces. Both directions pin "
            "their inputs, their runner, their invocation and their published "
            "result, the figure states what its denominator counts, and "
            "independence is declared. It is the twin every reject member below "
            "differs from in exactly one field."
        ),
    )

    # mrc-c-1 --------------------------------------------------------------
    mutable = copy.deepcopy(both)
    mutable[0]["inputs"].pop("ref")
    mutable[0]["inputs"]["version"] = "v0.1.0"
    add(
        kind="reject",
        condition="mrc-c-1",
        payload=record(sides=mutable, figure=whole_figure(6), independence=independent),
        cites=(
            "inputs named by a version string instead of a commit. The string "
            "resolves today and names a moving target: a re-tag changes what the "
            "claim was about without changing a character of the claim."
        ),
    )

    # mrc-c-2 --------------------------------------------------------------
    library_only = copy.deepcopy(both)
    library_only[1]["runner"].pop("ref")
    library_only[1]["runner"]["name"] = "our own implementation of the checks"
    add(
        kind="reject",
        condition="mrc-c-2",
        payload=record(sides=library_only, figure=whole_figure(24), independence=independent),
        cites=(
            "a side naming the implementation it used and not the driver that "
            "loaded the inputs. Both endpoints resolve and the run does not: "
            "this is the shape a cross-run takes when one side is a library and "
            "the adapter around it was never published."
        ),
    )
    add(
        kind="accept",
        condition="mrc-c-2",
        payload=record(
            sides=[
                side("forward"),
                side(
                    "reverse",
                    inputs_ref=REF_B,
                    runner_ref=None,
                    runner_digest="sha256:" + "c" * 64,
                    runner_name="a driver over our own implementation of the checks",
                    output_digest=OUT_B,
                ),
            ],
            figure=whole_figure(24),
            independence=independent,
        ),
        cites=(
            "the same side pinning the driver by digest rather than by "
            "repository. A digest is enough: the requirement is that the runner "
            "be obtainable and identifiable, not that it live anywhere in "
            "particular."
        ),
    )

    # mrc-c-3 --------------------------------------------------------------
    no_command = copy.deepcopy(both)
    no_command[1]["invocation"] = None
    add(
        kind="reject",
        condition="mrc-c-3",
        payload=record(sides=no_command, figure=whole_figure(24), independence=independent),
        cites=(
            "a side with no invocation. A reader holding the inputs and the "
            "runner still cannot know which subset was run, in which mode, or "
            "with which flags, and a cross-run whose two sides ran different "
            "subsets is not a cross-run."
        ),
    )
    add(
        kind="accept",
        condition="mrc-c-3",
        payload=record(
            sides=[
                side("forward"),
                side(
                    "reverse",
                    inputs_ref=REF_B,
                    runner_ref=RUNNER_B,
                    invocation=(
                        "python3 -m driver --fixtures ./fixtures --report report.json"
                    ),
                    output_digest=OUT_B,
                ),
            ],
            figure=whole_figure(24),
            independence=independent,
        ),
        cites="the same side with its invocation written out.",
    )

    # mrc-c-4 --------------------------------------------------------------
    no_digest = copy.deepcopy(both)
    no_digest[0]["output"].pop("digest")
    add(
        kind="reject",
        condition="mrc-c-4",
        payload=record(sides=no_digest, figure=whole_figure(6), independence=independent),
        cites=(
            "a result published without a digest. A third party can re-run it "
            "and has nothing to compare against but a prose table, and a prose "
            "table is where a rounding becomes invisible."
        ),
    )
    unpublished = copy.deepcopy(both)
    unpublished[0]["output"]["published"] = False
    add(
        kind="reject",
        condition="mrc-c-4",
        payload=record(sides=unpublished, figure=whole_figure(6), independence=independent),
        cites=(
            "a digest over a result nobody else holds. It reads as the strongest "
            "field in the record and it is the weakest: a digest a reader cannot "
            "check a file against is a promise about a file."
        ),
    )
    add(
        kind="accept",
        condition="mrc-c-4",
        payload=record(
            sides=[
                side("forward", output_digest="sha256:" + "d" * 64),
                side("reverse", inputs_ref=REF_B, runner_ref=RUNNER_B, output_digest=OUT_B),
            ],
            figure=whole_figure(6),
            independence=independent,
        ),
        cites="both results published, each with its digest.",
    )

    # mrc-c-5 --------------------------------------------------------------
    no_rule = copy.deepcopy(both)
    add(
        kind="reject",
        condition="mrc-c-5",
        payload=record(
            sides=no_rule,
            figure={
                "headline": headline(24, 24),
                "total": 24,
                "scored": 24,
                "notScored": [],
            },
            independence=independent,
        ),
        cites=(
            "a whole-numerator figure with no counting rule. Everything needed "
            "to redo the run is present, so the record is re-checkable and the "
            "figure is still not quotable: a reader cannot tell what the "
            "denominator counts."
        ),
    )
    compressed = copy.deepcopy(both)
    add(
        kind="reject",
        condition="mrc-c-5",
        payload=record(
            sides=compressed,
            figure={
                "headline": headline(24, 24),
                "total": 24,
                "scored": 18,
                "notScored": [
                    {
                        "count": 4,
                        "reason": "outside the runner's numeric range, declared out of scope",
                    },
                    {
                        "count": 2,
                        "reason": "needing schema validation the runner does not implement",
                    },
                ],
                "countingRule": (
                    "the denominator counts every member of the fixture set; six "
                    "members were deliberately not scored and are enumerated"
                ),
            },
            independence=independent,
        ),
        cites=(
            "the sharpest member here. The counting rule is stated, the unscored "
            "members are enumerated by name, and the headline still reads as a "
            "whole numerator. The record is honest one line down and the line a "
            "reader quotes is the compression. A checker that reads only the "
            "headline reports it as agreement on every member."
        ),
    )
    add(
        kind="accept",
        condition="mrc-c-5",
        payload=record(
            sides=copy.deepcopy(both),
            figure={
                "headline": headline(18, 24) + " members scored, the rest enumerated",
                "total": 24,
                "scored": 18,
                "notScored": [
                    {
                        "count": 4,
                        "reason": "outside the runner's numeric range, declared out of scope",
                    },
                    {
                        "count": 2,
                        "reason": "needing schema validation the runner does not implement",
                    },
                ],
                "countingRule": (
                    "the denominator of the headline counts the members that were "
                    "scored; the six that were not are enumerated and are not "
                    "counted as passes"
                ),
            },
            independence=independent,
        ),
        cites=(
            "the same run written so the headline and the counting rule agree. "
            "Nothing about the run changed and the number a reader carries away "
            "did."
        ),
    )

    # mrc-c-6 --------------------------------------------------------------
    add(
        kind="reject",
        condition="mrc-c-6",
        payload=record(sides=copy.deepcopy(both), figure=whole_figure(6)),
        cites=(
            "a record with no independence declaration. Everything needed to "
            "redo the run is present and the reader cannot tell whether the "
            "party that ran the inputs wrote them, which is the difference "
            "between corroboration and a self-report."
        ),
    )
    add(
        kind="accept",
        condition="mrc-c-6",
        payload=record(sides=copy.deepcopy(both), figure=whole_figure(6), independence=self_report),
        cites=(
            "a self-report that says so. It is re-checkable and it is not "
            "independent evidence, and both of those are readable off the "
            "record. Declaring the weaker position is what makes the record "
            "usable; a record that leaves it out is the one a reader has to "
            "guess about."
        ),
    )

    # environment ---------------------------------------------------------
    no_env = copy.deepcopy(both)
    no_env[0].pop("environment")
    add(
        kind="accept",
        condition="mrc-c-1",
        payload=record(sides=no_env, figure=whole_figure(6), independence=independent),
        cites=(
            "a record with one environment unrecorded. It stays re-checkable, "
            "because the four inputs are what a re-run needs, and the checker "
            "notes the gap: a result that turns out not to depend on the runtime "
            "is a stronger result, and nobody can establish that from a record "
            "that never named one."
        ),
    )

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
        "| `{id}` | {kind} | {cond} | {recheck} | {figure} | {party} |".format(
            id=entry["id"],
            kind=entry["kind"],
            cond=", ".join(entry["conditions"]),
            recheck="yes" if entry["expected"]["recheckable"] else "no",
            figure="honest" if entry["expected"]["figureMeansWhatItSays"] else "misleads",
            party=entry["expected"]["independence"],
        )
        for entry in manifest["vectors"]
    )
    conditions = "\n".join(
        "| `{key}` | {requires} Because {why}. |".format(
            key=key, requires=value["requires"], why=value["why"]
        )
        for key, value in sorted(CONDITIONS.items())
    )
    accept = manifest["counts"]["accept"]
    reject = manifest["counts"]["reject"]
    total = len(manifest["vectors"])
    return f"""# Conformance vectors (cross-run record contract)

Every member of this suite in one table. The subject under test is a **run
record**: the artifact a cross-implementation claim rests on, rather than any
protocol message.

This corpus is {total} vectors, of which {accept} a conformant verifier must
not fail closed on and {reject} it must reject.

The criterion is `../{CRITERION}` and `check_run_record.py` is that criterion
as code. This corpus is the checker's own conformance suite, so the criterion
is measured rather than asserted.

**Every member is synthetic.** Each is shaped after a defect observed in
published cross-run claims in open specification threads. None transcribes or
attributes a particular claim, and no party is named anywhere in this
directory: the shape is the thing under test, and a corpus that named parties
would be an accusation with a schema.

**Three columns, because they answer different questions.** `re-checkable`
asks whether a third party can obtain the same result from what is published.
`figure` asks whether the headline agrees with its own counting rule.
`independence` is one of independent, self-report or undeclared, and only the
last of those is a defect. A record can be fully re-checkable, carry a figure
nobody should quote, and be a declared self-report, and folding those into one
verdict is how each of them disappears.

Regenerate byte-identically: `python3 gen_vectors.py`.
Self-check: `aee-verify vectors-mcp-record-contract/` from the repository root.
Check a record: `python3 check_run_record.py records/<id>.json`.

## Conditions

| id | what it requires |
|---|---|
{conditions}

## Vectors

| id | kind | conditions | re-checkable | figure | independence |
|---|---|---|---|---|---|
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

    entries.sort(key=lambda entry: entry["id"])
    counts = {
        kind: sum(1 for entry in entries if entry["kind"] == kind)
        for kind in ("accept", "reject")
    }
    manifest = {
        "suite": SUITE,
        "subject": "a cross-implementation run record",
        "tracksUpstream": TRACKS_UPSTREAM,
        "criterion": CRITERION,
        "checker": "check_run_record.py",
        "conditions": CONDITIONS,
        "counts": counts,
        "corpusDigest": sha(b"".join(files[entry["record"]] for entry in entries)),
        "note": (
            "Every member is synthetic and no party is named. A reject member "
            "fails the criterion for one declared reason and differs from an "
            "accepting twin in one field, so a checker that refuses everything "
            "scores zero rather than full marks."
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
    print(
        f"wrote {len(files)} file(s): {counts['accept']} accept, {counts['reject']} reject, "
        f"corpus {manifest['corpusDigest'][:12]}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
