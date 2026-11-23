"""Checks the composite action adds to a replay, standard library only.

Every function here runs under ``python -S`` with nothing installed, because the
conformance mode (scripts/action-conformance.py) runs before any setup step and
the job summary (scripts/action-summary.py) must agree with it. Six things live
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
* ``split_command``: a verifier command line as argv, on Windows too.
"""

from __future__ import annotations

import json
import os
import re
import shlex
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
    and no member is named. ``filesOnDisk`` counts every file under the
    directory, so a directory with files and no MANIFEST.json is never read as
    an empty one.
    """
    manifest = manifest_of(corpus_dir)
    disk = files_on_disk(corpus_dir) if os.path.isdir(corpus_dir) else set()
    if manifest is None:
        return {
            "manifest": False,
            "listed": 0,
            "present": 0,
            "filesOnDisk": len(disk),
            "missingOnDisk": [],
            "missingFromReport": [],
            "reportGap": 0,
            "os": os.name,
        }
    members = listed_members(manifest)
    missing_disk = sorted(m["path"] for m in members if not _member_on_disk(m, disk))
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
            expected = _report_units(members, report.get("unit"))
            missing_report = sorted(i for i in expected if i not in scored)
            gap = len(missing_report)
    return {
        "manifest": True,
        "listed": len(members),
        "present": len(members) - len(missing_disk),
        "filesOnDisk": len(disk),
        "missingOnDisk": missing_disk,
        "missingFromReport": missing_report,
        "reportGap": gap,
        "os": os.name,
    }


def _member_on_disk(member: dict[str, Any], disk: set[str]) -> bool:
    """Whether a listed member is on this runner's disk.

    A member is a file, or a directory of files (the runtime corpora keep one
    directory per case, and list its files under ``files``). A directory is
    present when every file it lists is, or, listing none, when it holds one.
    """
    path = member["path"]
    if path in disk:
        return True
    listed = member["entry"].get("files")
    if isinstance(listed, dict) and listed:
        return all(f"{path}/{name}" in disk for name in listed)
    return any(f.startswith(path.rstrip("/") + "/") for f in disk)


RUNTIME_UNIT = "runtime scenario"


def _report_units(members: list[dict[str, Any]], unit: Any) -> list[str]:
    """The ids a report's rows must cover: member ids, or a runtime contract's scenario ids.

    A runtime replay scores each scenario once, and many members share one
    scenario (`runtime.scenario.id`), so its rows are compared with the set of
    scenarios the members name. Every other report scores members.
    """
    if unit != RUNTIME_UNIT:
        return [m["id"] for m in members]
    scenarios: list[str] = []
    for member in members:
        runtime = member["entry"].get("runtime")
        scenario = runtime.get("scenario") if isinstance(runtime, dict) else None
        name = scenario.get("id") if isinstance(scenario, dict) else None
        if isinstance(name, str) and name not in scenarios:
            scenarios.append(name)
    return scenarios


# ---------------------------------------------------------------- profiles


class _Number:
    """A number token as the text spells it: the json hooks below keep the spelling."""

    __slots__ = ("token",)

    def __init__(self, token: str) -> None:
        self.token = token


def _refuse_constant(name: str) -> Any:
    raise ValueError(f"{name} is not a JSON number")


def _parsed(text: str) -> Any:
    """``text`` parsed with every number kept as its token; raises ValueError.

    ``NaN`` and ``Infinity`` are refused rather than read as numbers: they are
    not JSON, so a member that carries one needs no float support to be
    rejected, and it stays inside ``integer-only``.
    """
    return json.loads(
        text,
        parse_int=_Number,
        parse_float=_Number,
        parse_constant=_refuse_constant,
        strict=False,
    )


def _number_features(token: str, found: set[str]) -> None:
    if not re.fullmatch(r"-?[0-9]+", token):
        found.add("non-integer-number")
    elif abs(int(token)) > SAFE_INTEGER:
        found.add("unsafe-integer")
    if re.fullmatch(r"-0(?:\.0+)?(?:[eE][+-]?[0-9]+)?", token):
        found.add("negative-zero")


def _string_features(value: str, found: set[str]) -> None:
    if any(0xD800 <= ord(ch) <= 0xDFFF for ch in value):
        found.add("surrogate-escape")
    if any(ord(ch) > 0x7F for ch in value):
        found.add("non-ascii")


def _scan_value(value: Any, found: set[str]) -> None:
    """Features of a value parsed by ``_parsed``, keys included."""
    stack = [value]
    while stack:
        item = stack.pop()
        if isinstance(item, _Number):
            _number_features(item.token, found)
        elif isinstance(item, str):
            _string_features(item, found)
        elif isinstance(item, dict):
            for key, inner in item.items():
                _string_features(key, found)
                stack.append(inner)
        elif isinstance(item, list):
            stack.extend(item)


def _scan_text(text: str, found: set[str]) -> None:
    """Features of JSON text, read from its tokens rather than a parsed value.

    Parsing to Python values would lose what a profile is about: ``1.0`` and
    ``1`` parse to equal numbers and ``-0`` to ``0``. So the text is parsed with
    every number kept as its token. Text that does not parse (a must-reject
    input) is scanned token by token, each string token decoded on its own, so
    an escaped backslash before ``u00e9`` reads as the ASCII text it is.
    """
    try:
        _scan_value(_parsed(text), found)
        return
    except (ValueError, RecursionError):
        pass
    for match in _STRING.finditer(text):
        token = match.group(0)
        try:
            _string_features(json.loads(token, strict=False), found)
        except ValueError:
            _string_features(_unescaped(token), found)
    stripped = _STRING.sub('""', text)
    for match in _NUMBER.finditer(stripped):
        start = match.start()
        if start and (stripped[start - 1].isalnum() or stripped[start - 1] in "_."):
            continue
        _number_features(match.group(0), found)


def _unescaped(token: str) -> str:
    """A string token that does not decode, with each ``\\uXXXX`` escape read by parity.

    Only an escape preceded by an even number of backslashes is an escape; the
    rest of the token is kept as written.
    """
    out: list[str] = []
    index = 0
    while index < len(token):
        ch = token[index]
        if ch == "\\" and index + 1 < len(token):
            nxt = token[index + 1]
            if nxt == "u" and re.fullmatch(r"[0-9a-fA-F]{4}", token[index + 2 : index + 6]):
                out.append(chr(int(token[index + 2 : index + 6], 16)))
                index += 6
                continue
            out.append(nxt)
            index += 2
            continue
        out.append(ch)
        index += 1
    return "".join(out)


def features_of(raw: bytes, declared: Iterable[str] | None = None) -> set[str]:
    """The profile features of one member.

    A manifest entry that declares ``features`` is taken at its word. Otherwise
    the member's input is scanned: ``input_raw`` verbatim, else the file's own
    top-level ``input`` member as the file spells it (the a2a vectors keep their
    numbers as written in the file), else the whole file. The ``input`` member
    is the top-level one of the parsed document, never the first key spelled
    ``input`` anywhere in the text: a nested ``"input": 1.5`` before an integer
    top-level input moved a member out of ``integer-only`` and excused its
    failure.
    """
    if declared is not None:
        return {str(f) for f in declared}
    text = raw.decode("utf-8", errors="surrogatepass")
    found: set[str] = set()
    try:
        document = _parsed(text)
    except (ValueError, RecursionError):
        document = None
    if isinstance(document, dict) and isinstance(document.get("input_raw"), str):
        _scan_text(document["input_raw"], found)
    elif isinstance(document, dict) and "input" in document:
        _scan_value(document["input"], found)
    elif document is not None:
        _scan_value(document, found)
    else:
        _scan_text(text, found)
    return found


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
    """Features of every listed member, by member id and by the id inside its file.

    An id two members both answer to (one member's manifest id is another's
    inner id) names no single member, so it is kept with no feature, which keeps
    a row carrying it inside every profile: one member's float input cannot
    excuse another member's failure.
    """
    manifest = manifest_of(corpus_dir)
    out: dict[str, set[str]] = {}
    if manifest is None:
        return out
    owner: dict[str, str] = {}
    ambiguous: set[str] = set()
    for member in listed_members(manifest):
        path = Path(corpus_dir) / member["path"]
        try:
            raw = path.read_bytes()
        except OSError:
            continue
        declared = member["entry"].get("features")
        found = features_of(raw, declared if isinstance(declared, list) else None)
        try:
            inner = json.loads(raw)
        except ValueError:
            inner = None
        names = {member["id"]}
        if isinstance(inner, dict) and isinstance(inner.get("id"), str):
            names.add(inner["id"])
        for name in names:
            if owner.setdefault(name, member["path"]) != member["path"]:
                ambiguous.add(name)
            out[name] = found
    for name in ambiguous:
        out[name] = set()
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


class _PairedDict(dict):  # type: ignore[type-arg]
    """A JSON object that also keeps every key-value pair as written, duplicates included."""

    def __init__(self, pairs: list[tuple[str, Any]]) -> None:
        super().__init__(pairs)
        self.pairs = pairs


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
        # Pairs, not a dict: json.loads keeps the last of two equal keys, so a
        # case listed `valid` and then `invalid` would be judged once, silently.
        document = json.loads(text, object_pairs_hook=_PairedDict)
        cases = document.get("cases", document) if isinstance(document, dict) else None
        if not isinstance(cases, _PairedDict):
            raise ValueError(f"{path}: a JSON expected-verdicts file maps each case to a verdict")
        pairs = [(str(k), str(v)) for k, v in cases.pairs]
    else:
        for number, line in enumerate(text.splitlines(), 1):
            # `#` starts a comment at the start of a line or after whitespace;
            # inside a path (`cases/#12.json`) it is part of the name.
            line = re.split(r"(?:^|\s)#", line, maxsplit=1)[0].strip()
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


# ---------------------------------------------------------------- command lines


def split_command(text: str, windows: bool = os.name == "nt") -> list[str]:
    """A verifier command line as argv.

    On Windows ``shlex`` runs in non-POSIX mode, which keeps the quotes around a
    quoted word (``"C:\\Program Files\\v.exe"`` stays quoted and names no
    file), so a word wrapped in one pair of quotes loses them. An empty command
    is refused: with no verifier the case file itself would be run.
    """
    words = shlex.split(text, posix=not windows)
    if windows:
        words = [w[1:-1] if len(w) > 1 and w[0] == w[-1] and w[0] in "\"'" else w for w in words]
    if not words:
        raise ValueError("no verifier named: the action runs `<verifier> <file>`")
    return words
