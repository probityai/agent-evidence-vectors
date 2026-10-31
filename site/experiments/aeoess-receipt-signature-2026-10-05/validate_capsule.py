#!/usr/bin/env python3
"""Check a public outside run's retained bytes without executing its code."""

from __future__ import annotations

import hashlib
import json
import math
import re
import zipfile
from collections import Counter
from pathlib import Path, PurePosixPath
from typing import Any

HERE = Path(__file__).resolve().parent
ROW = re.compile(r"^(v[0-9a-f]{16})\s+(\S+)\s+(\S+)\s+windows: (.+); no windows: (.+)$", re.MULTILINE)
TOTALS = re.compile(r"^totals: (\d+) vectors, (\d+) pass, (\d+) not honouring a SHOULD, (\d+) closing a gap, (\d+) fail;", re.MULTILINE)


def require(condition: bool, message: str) -> None:
    """Refuse an unsupported retained result."""
    if not condition:
        raise ValueError(message)


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Reject duplicate JSON names before interpretation."""
    result: dict[str, Any] = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON name")
        result[key] = value
    return result


def reject_constant(value: str) -> None:
    """Refuse nonfinite tokens outside the JSON number grammar."""
    raise ValueError(f"nonfinite JSON constant: {value}")


def finite_float(value: str) -> float:
    """Refuse exponent overflow rather than interpreting it as infinity."""
    result = float(value)
    require(math.isfinite(result), "nonfinite JSON number")
    return result


def load_json(raw: bytes) -> Any:
    """Read captured JSON without duplicate fields or nonfinite numbers."""
    return json.loads(raw, object_pairs_hook=unique_object,
                      parse_constant=reject_constant, parse_float=finite_float)


def safe_member(name: str) -> None:
    """Keep every retained path inside its declared archive namespace."""
    path = PurePosixPath(name)
    require(not path.is_absolute() and ".." not in path.parts, "unsafe source member")
    require(str(path) == name and "\\" not in name, "ambiguous source member")


def read_capsule(folder: Path) -> dict[str, bytes]:
    """Authenticate the complete selected member population and Git blobs."""
    manifest = load_json((folder / "source-manifest.json").read_bytes())
    raw = (folder / "selected-public-source.zip").read_bytes()
    require(len(raw) == manifest["archiveBytes"], "source archive size changed")
    require(hashlib.sha256(raw).hexdigest() == manifest["archiveSha256"], "source archive digest changed")
    pins = {entry["member"]: entry for entry in manifest["members"]}
    require(len(pins) == len(manifest["members"]), "source manifest repeats a member")
    with zipfile.ZipFile(folder / "selected-public-source.zip") as archive:
        names = archive.namelist()
        require(len(names) == len(set(names)) and set(names) == set(pins), "source population changed")
        result = {}
        for name in names:
            safe_member(name)
            body = archive.read(name)
            pin = pins[name]
            require(len(body) == pin["bytes"], "source member size changed")
            require(hashlib.sha256(body).hexdigest() == pin["sha256"], "source member digest changed")
            blob = hashlib.sha1(b"blob " + str(len(body)).encode() + b"\0" + body).hexdigest()
            require(blob == pin["gitBlob"], "source Git blob changed")
            result[name] = body
    return result


def check_record_digests(content: dict[str, bytes]) -> int:
    """Check the operator's original immutable digest set in full."""
    names = set()
    for line in content["record/SHA256SUMS.txt"].decode().splitlines():
        digest, name = line.split("  ")
        safe_member(name)
        require(name not in names, "original digest set repeats a member")
        names.add(name)
        require(hashlib.sha256(content["record/" + name]).hexdigest() == digest, "original record digest changed")
    record_names = {name.removeprefix("record/") for name in content if name.startswith("record/")}
    require(names == record_names - {"SHA256SUMS.txt"}, "original digest set omits a record")
    return len(names)


def expected_text(value: dict[str, Any]) -> str:
    """Render the corpus's declared verdict and optional diagnostic code."""
    return value["verdict"] + (" " + value["code"] if value["code"] is not None else "")


def check_reports(content: dict[str, bytes], manifest: dict[str, Any]) -> dict[str, int]:
    """Bind every outside answer to the exact declared member and both profiles."""
    require(content["record/report1.json"] == content["record/report2.json"], "repeated reports differ")
    require(content["record/run1.txt"] == content["record/run2.txt"], "repeated outputs differ")
    report = load_json(content["record/report1.json"])
    entries = {entry["id"]: entry for entry in manifest["vectors"]}
    rows = {row["id"]: row for row in report["vectors"]}
    require(len(entries) == len(manifest["vectors"]), "corpus repeats a member")
    require(len(rows) == len(report["vectors"]) and rows.keys() == entries.keys(), "outside report population changed")
    for identity, row in rows.items():
        entry = entries[identity]
        require(row["kind"] == entry["kind"], "outside report kind changed")
        require(row["verifierRan"] is True and row["status"] == "PASS", "outside result was not executed and passing")
        require(row["withWindows"] == expected_text(entry["expected"]), "windowed answer differs from declared fixture")
        require(row["withoutWindows"] == expected_text(entry["expectedWithoutWindows"]), "unwindowed answer differs from declared fixture")
        require(row["reasons"] == [], "passing result contains unresolved reasons")
    printed = log_rows(content["record/run1.txt"], entries)
    require(all(printed[identity] == (row["status"], row["withWindows"], row["withoutWindows"])
                for identity, row in rows.items()), "outside report differs from retained stdout")
    count = len(rows)
    require(report["verifier"]["vectorsExecuted"] == count == report["verifier"]["vectors"], "outside execution denominator changed")
    expected_totals = {"vectors": count, "pass": count, "fail": 0, "conform": count, "notHonoured": 0,
                       "closesGap": 0, "reasonParityMismatch": 0, "suiteRefusals": 0, "notExercised": 0}
    require(report["totals"] == expected_totals and report["notes"] == [], "outside report totals changed")
    return {"members": count, "executed": count, "passingFixtureComparisons": count, "profileAnswersPerRun": count * 2}


def check_identifiers(content: dict[str, bytes], manifest: dict[str, Any]) -> dict[str, Any]:
    """Recompute author integrity while preserving the outside run's coverage gap."""
    matches = {}
    uncovered = []
    preimages = {}
    for entry in manifest["vectors"]:
        raw = content["corpus/" + entry["file"]]
        context = entry.get("context")
        if context is not None:
            canonical = json.dumps(context, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
            commitment = content["corpus/" + context["commitment"]] if context.get("commitment") else b""
            raw += canonical + commitment
            uncovered.append(entry["id"])
        else:
            digest = hashlib.sha256(raw).hexdigest()
            matches[entry["id"]] = digest
        preimages[entry["id"]] = raw
        require("v" + hashlib.sha256(raw).hexdigest()[:16] == entry["id"], "corpus identifier does not recompute")
    expected_lines = []
    for entry in manifest["vectors"]:
        identity = entry["id"]
        expected_lines.append(identity + ("  " + matches[identity] + "  MATCH" if identity in matches else "  NOT COVERED (has a context)"))
    expected_lines.append("no-context identifiers matching: " + str(len(matches)))
    require(content["record/digests21.txt"].decode().splitlines() == expected_lines, "outside identifier coverage changed")
    corpus_digest = hashlib.sha256(b"".join(preimages[identity] for identity in sorted(preimages))).hexdigest()
    require(corpus_digest == manifest["corpusDigest"], "corpus digest does not recompute")
    return {"outsideContextFreeIdentifiers": len(matches), "outsideContextIdentifiersNotCovered": uncovered,
            "authorIntegrityIdentifiers": len(preimages), "authorIntegrityCorpusDigest": corpus_digest}


def log_rows(raw: bytes, entries: dict[str, Any]) -> dict[str, tuple[str, str, str]]:
    """Require one complete control row per member and derive its terminal counts."""
    text = raw.decode()
    parsed = ROW.findall(text)
    rows = {identity: (status, windows, without) for identity, kind, status, windows, without in parsed}
    require(len(rows) == len(parsed) and rows.keys() == entries.keys(), "control population changed")
    require(all(kind == entries[identity]["kind"] for identity, kind, *_ in parsed), "control kind changed")
    statuses = Counter(status for status, *_ in rows.values())
    require(set(statuses) <= {"PASS", "FAIL", "NOT-HONOURED", "CLOSES-GAP"}, "unknown control status")
    counts = (len(rows), statuses["PASS"], statuses["NOT-HONOURED"], statuses["CLOSES-GAP"], statuses["FAIL"])
    totals = TOTALS.findall(text)
    require(len(totals) == 1 and tuple(map(int, totals[0])) == counts, "control totals do not match rows")
    return rows


def check_always_valid(always: dict[str, tuple[str, str, str]], entries: dict[str, Any]) -> None:
    """Keep all-valid answers separate from the author's fixture grading."""
    require(all(w == n == "valid" for _, w, n in always.values()), "all-valid control answers changed")
    for identity, (status, _, _) in always.items():
        kind = entries[identity]["kind"]
        require(status == {"reject": "FAIL", "indeterminate": "NOT-HONOURED"}.get(kind, "PASS"), "all-valid control classification changed")


def check_fixture_answer(row: tuple[str, str, str], entry: dict[str, Any]) -> None:
    """Compare both recorded profiles without executing the verifier."""
    status, windows, without = row
    require(status == "PASS", "unmodified control status changed")
    require(windows == expected_text(entry["expected"]), "unmodified windowed answer changed")
    require(without == expected_text(entry["expectedWithoutWindows"]), "unmodified unwindowed answer changed")


def check_signature_mutation(mutation: dict[str, tuple[str, str, str]], entries: dict[str, Any]) -> int:
    """Require the failures to cover the one receipt's complete shared population."""
    affected = {identity for identity, entry in entries.items() if entry["file"] == "receipts/v814de39bf68212fc.json"}
    failed = {identity for identity, (status, _, _) in mutation.items() if status == "FAIL"}
    require(failed == affected, "signature mutation does not cover the shared receipt")
    for identity, (_, windows, without) in mutation.items():
        if identity in affected:
            require(windows == without == "invalid signature_invalid", "signature mutation answer changed")
        else:
            check_fixture_answer(mutation[identity], entries[identity])
    return len(affected)


def check_controls(content: dict[str, bytes], manifest: dict[str, Any]) -> dict[str, int]:
    """Check the three retained control populations and derive their counts."""
    entries = {entry["id"]: entry for entry in manifest["vectors"]}
    always = log_rows(content["record/ctrl1.txt"], entries)
    check_always_valid(always, entries)
    mutation = log_rows(content["record/ctrl2.txt"], entries)
    affected = check_signature_mutation(mutation, entries)
    original = log_rows(content["record/ctrl2ok.txt"], entries)
    for identity, row in original.items():
        check_fixture_answer(row, entries[identity])
    return {"alwaysValidFailures": sum(status == "FAIL" for status, _, _ in always.values()),
            "alwaysValidShouldRefusals": sum(status == "NOT-HONOURED" for status, _, _ in always.values()),
            "signatureMutationAffectedMembers": affected, "unmodifiedExplicitCorpusPasses": len(original)}


def derive(content: dict[str, bytes]) -> dict[str, Any]:
    """Derive finite published observations; this does not rerun a verifier."""
    manifest = load_json(content["corpus/MANIFEST.json"])
    return {"originalRecordDigestBindings": check_record_digests(content),
            "outsideVerifier": check_reports(content, manifest),
            "identifiers": check_identifiers(content, manifest),
            "controls": check_controls(content, manifest)}


def validate(folder: Path = HERE) -> dict[str, Any]:
    """Check the public capsule and its separately labeled derived report."""
    content = read_capsule(folder)
    for name in ("report1.json", "report2.json", "RUN.md"):
        require((folder / name).read_bytes() == content["record/" + name], "standalone original differs from capsule")
    result = derive(content)
    require(load_json((folder / "report.json").read_bytes()) == result, "derived report differs from retained observations")
    return result


if __name__ == "__main__":
    print(json.dumps(validate(), indent=2))
