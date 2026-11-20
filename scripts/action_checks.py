"""Checks the composite action adds to a replay, standard library only.

Every function here runs under ``python -S`` with nothing installed, because the
conformance mode (scripts/action-conformance.py) runs before any setup step and
the job summary (scripts/action-summary.py) must agree with it. Five things live
here, each answering one question a green run used to leave open:

* ``count_cases``: how many cases the corpus lists and how many are on this
  runner's disk, walked with ``os.walk`` and compared as POSIX paths, so a
  Windows runner counts the same files a Linux one does. A run that found no
  case is never a pass (``fail-on-no-vectors``), and a listed case that is not
  on disk or not in the report is named (``fail-on-missing-case``).
* ``features_of`` and ``split_by_profile``: which corpus members fall outside a
  declared profile (``integer-only`` and the rest), so a divergence outside the
  profile is counted on its own line and a divergence inside it still fails.
* ``controls``: what an always-accept and an always-reject verifier score on the
  same corpus. A corpus where either control does better than its share of
  must-accept or must-reject members cannot tell a verifier from a constant,
  and the summary says so.
* ``read_expected``: the expected-verdicts file of the conformance mode.
* ``ACCEPT_KINDS``: the member kinds that expect acceptance, across readers.
"""

from __future__ import annotations

import json
import os
import re
from collections.abc import Iterable
from pathlib import Path, PurePosixPath
from typing import Any

#: Member kinds that expect acceptance. The AEE corpus says ``accept``; the a2a
#: canonicalization corpus says ``MUST-ACCEPT``; a conformance expected-verdicts
#: file says ``valid``.
ACCEPT_KINDS = frozenset({"accept", "MUST-ACCEPT", "must-accept", "valid", "pass", "positive"})
REJECT_KINDS = frozenset({"reject", "MUST-REJECT", "must-reject", "invalid", "fail", "negative"})

SAFE_INTEGER = 2**53 - 1

#: Built-in profiles: each names the features a member must NOT have to be in
#: the profile. A profile file may name its own (see ``load_profile``).
PROFILES: dict[str, frozenset[str]] = {
    "integer-only": frozenset({"non-integer-number"}),
    "safe-integer": frozenset({"non-integer-number", "unsafe-integer"}),
    "ascii-only": frozenset({"non-ascii", "surrogate-escape"}),
}
FEATURES = frozenset(
    {"non-integer-number", "unsafe-integer", "negative-zero", "non-ascii", "surrogate-escape"}
)

_NUMBER = re.compile(r"-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?")
_STRING = re.compile(r'"(?:[^"\\]|\\.)*"', re.DOTALL)
_NON_ASCII_ESCAPE = re.compile(
    r"\\u(?:00[89a-fA-F][0-9a-fA-F]|0[1-9a-fA-F][0-9a-fA-F]{2}|[1-9a-fA-F][0-9a-fA-F]{3})"
)
_SURROGATE = re.compile(r"\\u[dD][89abAB][0-9a-fA-F]{2}|\\u[dD][c-fC-F][0-9a-fA-F]{2}")


# ---------------------------------------------------------------- corpus members


def manifest_of(corpus_dir: str | os.PathLike[str]) -> dict[str, Any] | None:
    """The corpus MANIFEST.json, or None when there is none to read."""
    path = Path(corpus_dir) / "MANIFEST.json"
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return document if isinstance(document, dict) else None


def listed_members(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    """Every member the manifest lists, as ``{"id", "path", "entry"}``.

    A member names its file as ``path`` or ``file``; its id is the entry's
    ``id`` when present, else the file's stem (the a2a corpus keeps its ids
    inside the files, and each file is named for its id).
    """
    out = []
    for entry in manifest.get("vectors", []) or []:
        if not isinstance(entry, dict):
            continue
        rel = entry.get("path") or entry.get("file")
        if not isinstance(rel, str):
            continue
        rel = PurePosixPath(rel.replace("\\", "/")).as_posix()
        member_id = entry.get("id") if isinstance(entry.get("id"), str) else PurePosixPath(rel).stem
        out.append({"id": member_id, "path": rel, "entry": entry})
    return out


def files_on_disk(corpus_dir: str | os.PathLike[str]) -> set[str]:
    """Every regular file under the corpus, as a POSIX path relative to it.

    ``os.walk`` and ``os.path.relpath`` rather than a glob: a glob pattern with
    a forward slash matched nothing on a Windows runner in a project whose CI
    then passed on zero vectors, and the count below is what refuses that.
    """
    root = os.fspath(corpus_dir)
    found: set[str] = set()
    for here, _dirs, files in os.walk(root):
        for name in files:
            rel = os.path.relpath(os.path.join(here, name), root)
            found.add(PurePosixPath(*Path(rel).parts).as_posix())
    return found


def count_cases(
    corpus_dir: str | os.PathLike[str], report: dict[str, Any] | None = None
) -> dict[str, Any]:
    """Listed, present and replayed counts, and every listed case that went missing.

    ``missingOnDisk`` names listed files this runner cannot see; ``missingFromReport``
    names listed members the replay did not score. A report that names a target
    scores only the members that target owns, so for it the count gap is given
    and no member is named.
    """
    manifest = manifest_of(corpus_dir)
    if manifest is None:
        return {
            "manifest": False,
            "listed": 0,
            "present": 0,
            "missingOnDisk": [],
            "missingFromReport": [],
            "reportGap": 0,
            "os": os.name,
        }
    members = listed_members(manifest)
    disk = files_on_disk(corpus_dir)
    missing_disk = sorted(m["path"] for m in members if m["path"] not in disk)
    missing_report: list[str] = []
    gap = 0
    if report is not None:
        rows = report.get("vectors") or []
        scored = {str(row.get("id")) for row in rows if isinstance(row, dict)}
        target = report.get("target")
        if isinstance(target, str):
            declared = ((manifest.get("targets") or {}).get(target) or {}).get("vectors")
            if isinstance(declared, int):
                gap = max(declared - len(rows), 0)
        else:
            missing_report = sorted(m["id"] for m in members if m["id"] not in scored)
            gap = len(missing_report)
    return {
        "manifest": True,
        "listed": len(members),
        "present": len(members) - len(missing_disk),
        "missingOnDisk": missing_disk,
        "missingFromReport": missing_report,
        "reportGap": gap,
        "os": os.name,
    }


# ---------------------------------------------------------------- profiles


def _scan_text(text: str, found: set[str]) -> None:
    """Features of JSON text, read from its tokens rather than a parsed value.

    Parsing first would lose what a profile is about: ``1.0`` and ``1`` parse
    to equal numbers, ``-0`` to ``0``, and an escaped lone surrogate to a
    string Python cannot encode.
    """
    for match in _STRING.finditer(text):
        token = match.group(0)
        if _SURROGATE.search(token):
            found.add("surrogate-escape")
        if any(ord(ch) > 0x7F for ch in token) or _NON_ASCII_ESCAPE.search(token):
            found.add("non-ascii")
    stripped = _STRING.sub('""', text)
    for match in _NUMBER.finditer(stripped):
        token = match.group(0)
        start = match.start()
        if start and (stripped[start - 1].isalnum() or stripped[start - 1] in "_."):
            continue
        if any(c in token for c in ".eE"):
            found.add("non-integer-number")
        elif abs(int(token)) > SAFE_INTEGER:
            found.add("unsafe-integer")
        if re.fullmatch(r"-0(?:\.0+)?(?:[eE][+-]?[0-9]+)?", token):
            found.add("negative-zero")


def features_of(raw: bytes, declared: Iterable[str] | None = None) -> set[str]:
    """The profile features of one member.

    A manifest entry that declares ``features`` is taken at its word. Otherwise
    the member's input is scanned: ``input_raw`` verbatim, else the file's own
    JSON text (the a2a vectors keep their numbers as written in the file).
    """
    if declared is not None:
        return {str(f) for f in declared}
    text = raw.decode("utf-8", errors="surrogatepass")
    found: set[str] = set()
    try:
        document = json.loads(text)
    except ValueError:
        document = None
    if isinstance(document, dict) and isinstance(document.get("input_raw"), str):
        _scan_text(document["input_raw"], found)
    elif isinstance(document, dict) and "input" in document:
        _scan_text(_member_text(text, "input"), found)
    else:
        _scan_text(text, found)
    return found


def _member_text(text: str, name: str) -> str:
    """The JSON text of one top-level member, sliced from the file as written.

    ``raw_decode`` finds where the value ends; the slice keeps every token as
    the file spells it, which the parsed value would not.
    """
    match = re.search(r'"' + re.escape(name) + r'"\s*:\s*', text)
    if match is None:
        return text
    try:
        _value, end = json.JSONDecoder().raw_decode(text, match.end())
    except ValueError:
        return text[match.end() :]
    return text[match.end() : end]


def load_profile(spec: str) -> dict[str, Any]:
    """A profile by built-in name, or from a JSON file.

    A file is ``{"name": ..., "excludes": [features], "outOfProfile": [ids]}``;
    either list may be absent. Several built-in names may be joined with commas.
    """
    spec = spec.strip()
    if os.path.isfile(spec):
        document = json.loads(Path(spec).read_text(encoding="utf-8"))
        if not isinstance(document, dict):
            raise ValueError(f"profile file {spec} is not a JSON object")
        named = frozenset(str(f) for f in document.get("excludes", []))
        if named - FEATURES:
            raise ValueError(
                f"profile file {spec} names unknown features {sorted(named - FEATURES)}"
            )
        return {
            "name": str(document.get("name", spec)),
            "excludes": named,
            "ids": frozenset(str(i) for i in document.get("outOfProfile", [])),
        }
    names = [n.strip() for n in spec.split(",") if n.strip()]
    if not names or any(n not in PROFILES for n in names):
        raise ValueError(
            f"profile {spec!r} is neither a file nor built-in names; the built-in "
            f"profiles are {', '.join(sorted(PROFILES))}"
        )
    excludes: frozenset[str] = frozenset().union(*(PROFILES[n] for n in names))
    return {"name": ",".join(names), "excludes": excludes, "ids": frozenset()}


def member_features(corpus_dir: str | os.PathLike[str]) -> dict[str, set[str]]:
    """Features of every listed member, by member id."""
    manifest = manifest_of(corpus_dir)
    out: dict[str, set[str]] = {}
    if manifest is None:
        return out
    for member in listed_members(manifest):
        path = Path(corpus_dir) / member["path"]
        try:
            raw = path.read_bytes()
        except OSError:
            continue
        declared = member["entry"].get("features")
        out[member["id"]] = features_of(raw, declared if isinstance(declared, list) else None)
        try:
            inner = json.loads(raw)
        except ValueError:
            inner = None
        if isinstance(inner, dict) and isinstance(inner.get("id"), str):
            out[inner["id"]] = out[member["id"]]
    return out


def split_by_profile(
    report: dict[str, Any], features: dict[str, set[str]], profile: dict[str, Any]
) -> dict[str, Any]:
    """In-profile and out-of-profile counts of a report's rows.

    A row whose member has any excluded feature, or whose id the profile names,
    is out of profile. A row whose member's features could not be read is kept
    IN profile, so an unreadable member can never hide a failure.
    """
    counts = {
        "in": {"vectors": 0, "pass": 0, "fail": 0},
        "out": {"vectors": 0, "pass": 0, "fail": 0},
    }
    out_ids: list[str] = []
    in_failures: list[str] = []
    for row in report.get("vectors") or []:
        row_id = str(row.get("id"))
        feats = features.get(row_id, set())
        outside = bool(feats & profile["excludes"]) or row_id in profile["ids"]
        side = counts["out" if outside else "in"]
        side["vectors"] += 1
        passed = row.get("status") == "PASS"
        side["pass" if passed else "fail"] += 1
        if outside:
            out_ids.append(row_id)
        elif not passed:
            in_failures.append(row_id)
    return {
        "profile": profile["name"],
        "excludes": sorted(profile["excludes"]),
        "inProfile": counts["in"],
        "outOfProfile": counts["out"],
        "outOfProfileIds": out_ids,
        "inProfileFailures": in_failures,
    }


# ---------------------------------------------------------------- null controls


def kind_shares(kinds: Iterable[str]) -> tuple[int, int, int]:
    """(must-accept, must-reject, total) over member kinds."""
    kinds = list(kinds)
    accept = sum(1 for k in kinds if k in ACCEPT_KINDS)
    reject = sum(1 for k in kinds if k in REJECT_KINDS)
    return accept, reject, len(kinds)


def controls(
    kinds: list[str], accept_passed: int | None, reject_passed: int | None
) -> dict[str, Any]:
    """The two null controls against the corpus's must-accept and must-reject shares.

    ``accept_passed`` and ``reject_passed`` are how many members an
    always-accept and an always-reject verifier passed (None when the control
    could not be scored). The corpus discriminates when neither control passes
    more members than its share, and neither passes them all.
    """
    accept, reject, total = kind_shares(kinds)
    findings = [
        finding
        for finding in (
            _control_finding("accept", accept_passed, accept, total),
            _control_finding("reject", reject_passed, reject, total),
        )
        if finding
    ]
    scored = accept_passed is not None and reject_passed is not None
    return {
        "total": total,
        "mustAccept": accept,
        "mustReject": reject,
        "alwaysAccept": accept_passed,
        "alwaysReject": reject_passed,
        "discriminates": (not findings) if scored else None,
        "findings": findings,
    }


def _control_finding(mode: str, passed: int | None, share: int, total: int) -> str | None:
    """Why one control shows the corpus does not discriminate, or None."""
    if passed is None or not total:
        return None
    if passed > share:
        return (
            f"always-{mode} passes {passed} of {total}, more than the {share} "
            f"members that must be {mode}ed"
        )
    if passed == total:
        return f"always-{mode} passes all {total}"
    return None


def controls_line(result: dict[str, Any]) -> str:
    """One summary line for the controls."""

    def cell(value: int | None) -> str:
        return "not scored" if value is None else f"{value} of {result['total']}"

    head = (
        f"Null controls: always-accept {cell(result['alwaysAccept'])}, "
        f"always-reject {cell(result['alwaysReject'])} "
        f"(must-accept {result['mustAccept']}, must-reject {result['mustReject']})."
    )
    if result["discriminates"] is None:
        return head + " A control was not scored, so whether the corpus discriminates is unknown."
    if result["discriminates"]:
        return head + " The corpus discriminates: neither control passes more than its share."
    return head + " **The corpus does not discriminate:** " + "; ".join(result["findings"]) + "."


# ---------------------------------------------------------------- expected verdicts

_VALID = {"valid", "accept", "pass", "must-accept", "ok", "0"}
_INVALID = {"invalid", "reject", "fail", "must-reject", "1"}


def read_expected(path: str | os.PathLike[str]) -> dict[str, str]:
    """An expected-verdicts file: case path to ``valid`` or ``invalid``.

    Two shapes. Text: one case per line, ``<path> <verdict>`` (``#`` starts a
    comment), the layout of a ``verify-expected.txt``. JSON: ``{"cases":
    {"<path>": "<verdict>"}}`` or a flat object of the same. Paths are relative
    to the cases root and compared as POSIX paths.
    """
    text = Path(path).read_text(encoding="utf-8")
    pairs: list[tuple[str, str]] = []
    stripped = text.lstrip()
    if stripped.startswith("{"):
        document = json.loads(text)
        cases = document.get("cases", document) if isinstance(document, dict) else None
        if not isinstance(cases, dict):
            raise ValueError(f"{path}: a JSON expected-verdicts file maps each case to a verdict")
        pairs = [(str(k), str(v)) for k, v in cases.items()]
    else:
        for number, line in enumerate(text.splitlines(), 1):
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            parts = line.rsplit(None, 1)
            if len(parts) != 2:
                raise ValueError(f"{path}:{number}: expected `<case> <verdict>`, got {line!r}")
            pairs.append((parts[0], parts[1]))
    out: dict[str, str] = {}
    for case, verdict in pairs:
        key = PurePosixPath(case.replace("\\", "/")).as_posix()
        word = verdict.strip().lower()
        if word in _VALID:
            out[key] = "valid"
        elif word in _INVALID:
            out[key] = "invalid"
        else:
            raise ValueError(f"{path}: case {case!r} has verdict {verdict!r}, not valid or invalid")
    if len(out) != len(pairs):
        raise ValueError(f"{path}: a case is listed twice")
    return out
