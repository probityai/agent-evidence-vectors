#!/usr/bin/env python3
"""Run this corpus against an ANCHORS stream verifier.

    python3 run_verifier.py --verifier /path/to/anchors_verify.py
    python3 run_verifier.py --verifier a.py --verifier b.py --label v0.4 --label v0.10

The verifier reads the witness platform over the network. A corpus whose
verdict depends on a live fetch has a verdict that expires, so every member
carries the bytes the platform would serve and this runner installs them
before the module is asked anything. It then replaces the module's own
fetchers with a function that raises, so a build that reaches for a socket
fails here instead of returning a number nobody can reproduce.

What is reproduced is the outcome path of the verifier's own ``main``: the
same three exception arms and the same call to its classifier. What is
replaced is the platform read. Nothing else is stubbed.

Exit 0 when every member answered as its manifest entry expects, 1 otherwise.
A non-zero exit is the interesting case: it names, per member, the outcome and
the stop reason observed against the ones the corpus requires.
"""

from __future__ import annotations

import argparse
import base64
import importlib.util
import inspect
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))


class Networked(RuntimeError):
    """The verifier asked for a URL during a run that supplies every byte."""


def load_module(path: str):
    name = "anchors_verify_" + os.path.basename(path).replace(".", "_")
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise SystemExit(f"FAIL: {path} is not importable as a Python module")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    for attribute in ("verify_from_bytes", "classify_verification_outcome", "bytes_to_lines"):
        if not hasattr(module, attribute):
            raise SystemExit(
                f"FAIL: {path} carries no {attribute}, so this runner cannot "
                "reproduce its outcome path without guessing at one."
            )
    return module


def seal(module) -> None:
    def refuse(*_args, **_kwargs):
        raise Networked(
            "the verifier reached for the network during a run that pins every "
            "byte it needs"
        )

    for attribute in ("fetch_url", "fetch_repo_lines", "fetch_json"):
        if hasattr(module, attribute):
            setattr(module, attribute, refuse)


def platform_bytes(entry: dict) -> dict:
    with open(os.path.join(HERE, entry["witness"]), encoding="utf-8") as handle:
        witness = json.load(handle)
    return witness


def observe(module, entry: dict, expect_repo: str) -> tuple[str, int, str | None, str]:
    """Return (outcome, exit code, stop reason, message) for one member."""
    with open(os.path.join(HERE, entry["stream"]), "rb") as handle:
        stream = handle.read()
    with open(os.path.join(HERE, entry["sidecar"]), "rb") as handle:
        sidecar = handle.read()
    witness = platform_bytes(entry)

    decode = base64.b64decode
    by_ref = {
        (ref["repo"], ref["commit"]): module.bytes_to_lines(decode(ref["bytesBase64"]))
        for ref in witness["byRef"]
    }
    reachable = {
        (ref["repo"], ref["commit"]): bool(ref["reachableFromDefaultBranch"])
        for ref in witness["byRef"]
    }
    active = witness["activeWitness"]
    by_ref.setdefault(
        (active["repo"], active["commit"]),
        module.bytes_to_lines(decode(active["bytesBase64"])),
    )
    reachable.setdefault((active["repo"], active["commit"]), True)

    keywords = {
        "check_witness_platform": True,
        "expect_witness_repo": expect_repo,
        "witness_lines_by_ref": by_ref,
        "witness_lines": module.bytes_to_lines(decode(active["bytesBase64"])),
        "main_lines": module.bytes_to_lines(decode(witness["defaultBranch"]["bytesBase64"])),
    }
    signature = inspect.signature(module.verify_from_bytes)
    if "commit_reachability" in signature.parameters:
        keywords["commit_reachability"] = reachable

    classify = getattr(module, "_rejection_class", None)
    try:
        result = module.verify_from_bytes(stream, sidecar, **keywords)
    except getattr(module, "VerifyUnattested", ()) as exc:
        reason = classify(exc) if classify else "unattested"
        return "VERIFY UNATTESTED", 2, reason, str(exc)
    except module.VerifyError as exc:
        reason = classify(exc) if classify else "verify_error"
        return "VERIFY FAILED", 1, reason, str(exc)

    classifier = inspect.signature(module.classify_verification_outcome)
    classify_keywords = {"expect_witness_repo": expect_repo}
    if "presented_lines" in classifier.parameters:
        classify_keywords["presented_lines"] = module.bytes_to_lines(stream)
    code, _stream_name, message = module.classify_verification_outcome(
        result, **classify_keywords
    )
    return message.split(":", 1)[0].strip(), code, None, message


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="run the corpus against a verifier")
    parser.add_argument(
        "--verifier",
        action="append",
        required=True,
        help="path to an anchors_verify.py; repeatable",
    )
    parser.add_argument(
        "--label",
        action="append",
        default=None,
        help="a name for the matching --verifier, used in the report",
    )
    parser.add_argument(
        "--reason-map",
        default=os.path.join(HERE, "reason-map", "aos-anchors-verify.json"),
        help=(
            "maps this corpus's stop-reason vocabulary onto one implementation's "
            "prose; needed only because the format publishes no reason codes"
        ),
    )
    parser.add_argument(
        "--expect",
        help=(
            "a recorded agreement file. With it the runner becomes a RATCHET: it "
            "refuses only when a member that agreed in the recording stops "
            "agreeing, and says nothing about the members already recorded as "
            "disagreeing. A build gate that demanded full agreement would refuse "
            "on the day it landed, which is a gate nobody keeps"
        ),
    )
    parser.add_argument(
        "--write-expect",
        help="record the current agreement to this file and exit",
    )
    parser.add_argument(
        "--json",
        dest="as_json",
        action="store_true",
        help="write the full observation table as JSON on stdout",
    )
    args = parser.parse_args(argv[1:])
    labels = args.label or []
    if labels and len(labels) != len(args.verifier):
        raise SystemExit("FAIL: --label was given a different number of times than --verifier")
    labels = labels or [os.path.basename(path) for path in args.verifier]

    with open(args.reason_map, encoding="utf-8") as handle:
        reasons = json.load(handle)["reasons"]
    with open(os.path.join(HERE, "MANIFEST.json"), encoding="utf-8") as handle:
        manifest = json.load(handle)
    expect_repo = manifest["target"].split()[0]

    report: dict[str, list[dict]] = {}
    failures = 0
    for path, label in zip(args.verifier, labels, strict=True):
        rows = score(load_module(path), manifest, expect_repo, reasons)
        failures += sum(1 for row in rows if not row["agrees"])
        report[label] = rows

    if args.write_expect:
        recorded = {
            label: {row["id"]: bool(row["agrees"]) for row in rows}
            for label, rows in report.items()
        }
        with open(args.write_expect, "w", encoding="utf-8") as handle:
            json.dump(recorded, handle, indent=2, sort_keys=True)
            handle.write("\n")
        print(f"wrote {args.write_expect}")
        return 0

    if args.expect:
        return ratchet(report, args.expect)

    if args.as_json:
        json.dump(report, sys.stdout, indent=2)
        sys.stdout.write("\n")
        return 1 if failures else 0

    render(report)
    return 1 if failures else 0


def ratchet(report: dict[str, list[dict]], path: str) -> int:
    """Refuse a member that agreed in the recording and no longer does.

    The corpus does not agree with any published build on every member, so a
    gate demanding full agreement refuses on the day it lands and gets removed
    the day after. This one carries a recording instead: it is silent about
    what already disagreed, and it fires the moment a passing member stops
    passing. A new member that agrees is recorded on the next run; a new member
    that does not is reported and does not fail the build, because a corpus
    growing is not the build breaking.
    """
    with open(path, encoding="utf-8") as handle:
        recorded = json.load(handle)
    regressions, unrecorded = [], []
    for label, rows in report.items():
        known = recorded.get(label)
        if known is None:
            print(f"{label}: no recording for this build; nothing to ratchet against")
            continue
        for row in rows:
            was = known.get(row["id"])
            if was is None:
                unrecorded.append((label, row))
            elif was and not row["agrees"]:
                regressions.append((label, row))
    for label, row in unrecorded:
        print(
            f"   new  {label} {row['id']} {','.join(row['conditions'])}: "
            f"{'agrees' if row['agrees'] else 'does not agree'}, not in the recording"
        )
    for label, row in regressions:
        print(
            f"  BROKE {label} {row['id']} {','.join(row['conditions'])}: agreed in the "
            f"recording, now {row['observedOutcome']} (exit {row['observedExit']}) "
            f"{row['observedMessage'][:80]}"
        )
    if regressions:
        print(f"\n{len(regressions)} member(s) that agreed no longer agree.")
        return 1
    print("ratchet: every member that agreed in the recording still agrees")
    return 0


def score(module, manifest: dict, expect_repo: str, reasons: dict) -> list[dict]:
    """Every member's observation against one build, verdict and reason alike."""
    seal(module)
    rows = []
    for entry in manifest["vectors"]:
        expected = entry["expected"]
        try:
            outcome, code, reason, message = observe(module, entry, expect_repo)
            networked = False
        except Networked as exc:
            outcome, code, reason, message, networked = "NETWORK", -1, None, str(exc), True
        verdict_agrees = (
            outcome == expected["outcome"]
            and code == expected["exit"]
            and not networked
        )
        # The reason is the half the verdict column cannot carry. A member
        # that stopped at the right verdict from a guard that fired before
        # the property was evaluated has not evaluated the property, and a
        # runner scoring only the verdict would award it full marks.
        declared = expected["stopReason"]
        if declared is None:
            reason_agrees = True
        else:
            needle = reasons.get(declared)
            reason_agrees = bool(
                verdict_agrees
                and needle
                and needle.lower() in (message or "").splitlines()[0].lower()
            )
        agrees = verdict_agrees and reason_agrees
        rows.append(
            {
                "id": entry["id"],
                "kind": entry["kind"],
                "conditions": entry["conditions"],
                "expectedOutcome": expected["outcome"],
                "expectedExit": expected["exit"],
                "expectedStopReason": expected["stopReason"],
                "observedOutcome": outcome,
                "observedExit": code,
                "observedStopReason": reason,
                "observedMessage": message.splitlines()[0] if message else "",
                "verdictAgrees": verdict_agrees,
                "reasonAgrees": reason_agrees,
                "agrees": agrees,
            }
        )
    return rows

def render(report: dict[str, list[dict]]) -> None:
    for label, rows in report.items():
        disagreeing = [row for row in rows if not row["agrees"]]
        print(f"== {label}: {len(rows) - len(disagreeing)} of {len(rows)} agree")
        right_verdict_wrong_reason = [
            row for row in disagreeing if row["verdictAgrees"] and not row["reasonAgrees"]
        ]
        if right_verdict_wrong_reason:
            print(
                f"   {len(right_verdict_wrong_reason)} of those reached the "
                "expected verdict and stopped somewhere else"
            )
        for entry_row in disagreeing:
            print(
                "   {id} {conds}: expected {eo} (exit {ee}), observed {oo} "
                "(exit {oe}) {msg}".format(
                    id=entry_row["id"],
                    conds=",".join(entry_row["conditions"]),
                    eo=entry_row["expectedOutcome"],
                    ee=entry_row["expectedExit"],
                    oo=entry_row["observedOutcome"],
                    oe=entry_row["observedExit"],
                    msg=entry_row["observedMessage"][:70],
                )
            )


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
