"""The cases the Go restart-records reader is held to, judged by the Python reader.

Each member of the corpus reaches its rule with one spelling, so most checks of a
reader are judged by one input each. This file takes every accepting record of the
corpus and both accepting bundles, changes each value in them in the ways that
decide a rule (removed, null, of another type, empty, every closed value of the
documents, earlier and later times, boundary counts), and keeps what the Python
checker answers for every variant in ``corpora/testdata/restart-records.json.gz``.
It adds byte-level variants (duplicate members, NaN, a BOM, a lone surrogate, an
integer past CPython's digit limit) and bundles whose digests are assigned, so that
a predecessor cycle can be built at all. The Go test
``TestRestartRecordsAgreesWithPython`` replays every variant and requires the same
verdict and reason, and then switches each Go rule off in turn and requires some
variant to notice. Regenerate with:

    AEV_WRITE_RESTART_RECORDS=1 uv run --extra dev pytest \\
        vectors-restart-records/tests/test_go_parity.py
"""

from __future__ import annotations

import base64
import copy
import functools
import gzip
import hashlib
import importlib.util
import json
import os
import sys
import types
from collections.abc import Iterator
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
REPO = ROOT.parent
FIXTURE = REPO / "corpora" / "testdata" / "restart-records.json.gz"


def _load(name: str, path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules.setdefault(name, module)
    spec.loader.exec_module(module)
    return module


generator = _load("restart_records_generator", ROOT / "gen_vectors.py")
checker = generator.checker
MANIFEST: dict[str, Any] = json.loads((ROOT / "MANIFEST.json").read_text(encoding="utf-8"))

DELETE = object()
TIMES = ("2026-01-01T00:00:00Z", "2026-01-10T09:59:59Z", "2026-01-10T12:00:00Z",
         "2026-01-12T00:00:00Z", "2027-12-31T23:59:59Z", "2024-02-29T00:00:00Z",
         "2023-02-29T00:00:00Z", "2026-13-01T00:00:00Z", "2026-01-01T24:00:00Z",
         "2026-01-01T23:59:60Z", "0000-01-01T00:00:00Z", "0001-01-01T00:00:00Z",
         "2026-01-01T00:00:00z", "2026-01-01 00:00:00Z", "2026-01-01T00:00:00Z\n",
         "2026-01-01T00:00:00.5Z", "٢٠٢٦-01-01T00:00:00Z")
URLS = ("https://", "https://a", "http://ops.example.com", "https://a b", "https://a\n",
        "https://a b", "https://a b", "https://a\x1cb", "https://a\x85b",
        "https://a﻿b", "HTTPS://a")
SHAS = ("0" * 64, "A" * 64, "0" * 63, "0" * 65, "0" * 64 + "\n", "g" * 64)
NUMBERS = (0, 1, 2, 5, 6, 40, 1000, -1, 1.5, 1.0)
GENERIC = ("", "x", " ", "unknown", "not_established")
CLOSED: tuple[str, ...] = tuple(sorted(
    {v for values in checker.REGISTRY.values() for v in values}
    | checker.ROLES | checker.AUTHORITY | checker.PART_STATES | checker.COVERAGE
    | checker.SINK_KINDS | checker.VANTAGES | checker.RESULTS | checker.SLOTS
    | {"listed", "none_observed"} | set(checker.TYPE.values())))
CREDENTIALS = ("https://idp.example.org/credentials/c-01",
               "https://idp.example.org/credentials/c-02",
               "https://idp.example.org/credentials/c-09")


def encode(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def answer(got: tuple[str, str]) -> list[str]:
    return [got[0], got[1]]


def record_answer(data: bytes) -> list[str]:
    return answer(checker.check_record_bytes(data))


def bundle_answer(files: dict[str, bytes]) -> list[str]:
    try:
        return answer(checker.check_bundle_files(files))
    except checker.Unreadable:
        return ["unreadable", ""]


def leaves(value: Any, path: tuple[Any, ...] = ()) -> Iterator[tuple[Any, ...]]:
    yield path
    if isinstance(value, dict):
        for key in sorted(value):
            yield from leaves(value[key], (*path, key))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from leaves(item, (*path, index))


def get(value: Any, path: tuple[Any, ...]) -> Any:
    for step in path:
        value = value[step]
    return value


def replaced(base: Any, path: tuple[Any, ...], new: Any) -> Any:
    if not path:
        return new
    out = copy.deepcopy(base)
    parent = get(out, path[:-1])
    if new is DELETE:
        del parent[path[-1]]
    else:
        parent[path[-1]] = new
    return out


def _string_candidates(value: str) -> list[Any]:
    if checker.TIME_RE.fullmatch(value):
        return [*TIMES, value + "\n"]
    if value.startswith("https://") and value not in checker.TYPE.values():
        return [*URLS, value + "\n", value + "/", *CREDENTIALS]
    if checker.SHA_RE.fullmatch(value):
        return list(SHAS)
    return [*GENERIC, *CLOSED, value.upper(), value + "\n"]


def candidates(value: Any) -> list[Any]:
    """The replacements tried at one place in a record."""
    found: list[Any] = [None, True]
    if isinstance(value, str):
        found += [1, [value], *_string_candidates(value)]
    elif isinstance(value, bool):
        found += [1, "true"]
    elif isinstance(value, int):
        found += [str(value), *NUMBERS, value + 1, value - 1]
    elif isinstance(value, list):
        found += [{}, "x", []]
        if value:
            found += [[*value, value[0]], list(reversed(value)), value[:1], [None],
                      [*value, *CREDENTIALS[:1]]]
            if all(isinstance(v, str) for v in value):
                found.append(sorted(value, reverse=True))
    elif isinstance(value, dict):
        found += [[], "x", {}, {**value, "unexpected_member": 1}]
    return found


def variants(base: Any) -> Iterator[tuple[tuple[Any, ...], dict[str, Any], Any]]:
    """Each place in base, each edit there, and the edited value."""
    for path in leaves(base):
        options = candidates(get(base, path))
        if path and isinstance(get(base, path[:-1]), dict):
            options = [DELETE, *options]
        for new in options:
            edit = {"op": "delete"} if new is DELETE else {"op": "set", "value": new}
            yield path, edit, replaced(base, path, new)


def _members(shape: str) -> list[dict[str, Any]]:
    return [e for e in MANIFEST["vectors"] if e["kind"] == "accept" and e["shape"] == shape]


def record_cases() -> dict[str, Any]:
    bases = [json.loads((ROOT / e["path"] / "statement.json").read_bytes())
             for e in _members("record")]
    out: list[dict[str, Any]] = []
    for index, base in enumerate(bases):
        seen: set[bytes] = set()
        for path, edit, value in variants(base):
            data = encode(value)
            if data in seen:
                continue
            seen.add(data)
            out.append({"base": index, "path": list(path), **edit, "want": record_answer(data)})
    return {"bases": bases, "cases": out}


def _control_bytes() -> bytes:
    entry = next(e for e in MANIFEST["vectors"] if e["id"] == "revocation-boundary-control")
    return (ROOT / entry["path"] / "statement.json").read_bytes()


def raw_cases() -> list[dict[str, Any]]:
    """Byte-level variants: what a parser accepts decides the answer before any rule."""
    control = _control_bytes()
    value = json.loads(control)
    text = control.decode()
    big = "1" * 4300
    edits = [
        control,
        control + b"\n \t\r\n",
        b" " + control,
        b"\xef\xbb\xbf" + control,
        control + b"x",
        control + b"{}",
        control.replace(b'"attempts": 40', b'"attempts": 40, "attempts": 40', 1),
        control.replace(b'"vantage": "sink_side"',
                        b'"vantage": "sink_side", "vantage": "sink_side"', 1),
        control.replace(b'"attempts": 40', b'"attempts": NaN', 1),
        control.replace(b'"attempts": 40', b'"attempts": Infinity', 1),
        control.replace(b'"attempts": 40', b'"attempts": -Infinity', 1),
        control.replace(b'"attempts": 40', b'"attempts": 1e400', 1),
        control.replace(b'"attempts": 40', b'"attempts": 4E1', 1),
        control.replace(b'"attempts": 40', b'"attempts": 40.0', 1),
        control.replace(b'"postRevocationCommits": 0', b'"postRevocationCommits": -0', 1),
        control.replace(b'"attempts": 40', b'"attempts": ' + big.encode(), 1),
        control.replace(b'"attempts": 40', b'"attempts": ' + big.encode() + b"1", 1),
        control.replace(b'"note": 1', b"", 1),
        control.replace(b'"the transaction commit"', b'"the transaction \\ud800commit"', 1),
        control.replace(b'"the transaction commit"', b'"the transaction \\udc00commit"', 1),
        control.replace(b'"the transaction commit"',
                        b'"the transaction \\ud83d\\ude00commit"', 1),
        control.replace(b'"the transaction commit"', b'"the transaction \\\\ud800commit"', 1),
        control.replace(b'"the transaction commit"', b'"the transaction \xffcommit"', 1),
        control.replace(b'"the transaction commit"', b'"the transaction \tcommit"', 1),
        control.replace(b'"the transaction commit"', b'"the transaction \\u0000commit"', 1),
        control.replace(b'"the transaction commit"', b'"the transaction \xe2\x80\xa8commit"', 1),
        control.replace(b'"sink_side"', b'"sink\\u005fside"', 1),
        control.replace(b"]\n}", b"],\n}", 1),
        text.replace('"attempts": 40', '"attempts": 40 ', 1).encode("utf-16"),
        encode(value),
        b"", b"null", b"[]", b"{}", b'"x"', b"1", b"[" + control + b"]",
    ]
    out = []
    seen: set[bytes] = set()
    for data in edits:
        if data in seen:
            continue
        seen.add(data)
        out.append({"bytes": base64.b64encode(data).decode(), "want": record_answer(data)})
    return out


def _bundle_files(entry: dict[str, Any]) -> dict[str, bytes]:
    directory = ROOT / entry["path"]
    return {name: (directory / name).read_bytes() for name in sorted(entry["files"])}


def _relinked(records: dict[str, Any], name: str, value: Any) -> dict[str, bytes] | None:
    before = {n: generator._sha(generator.statement_bytes(r)) for n, r in records.items()}
    changed = {**records, name: value}
    try:
        return generator.relink(changed, before)  # type: ignore[no-any-return]
    except (KeyError, TypeError, AttributeError, IndexError):
        return None


def _overlay(base: dict[str, bytes], files: dict[str, bytes | None]) -> dict[str, bytes]:
    out = dict(base)
    for name, data in files.items():
        if data is None:
            out.pop(name, None)
        else:
            out[name] = data
    return out


def _stored(files: dict[str, bytes | None]) -> dict[str, str | None]:
    return {name: None if data is None else base64.b64encode(data).decode()
            for name, data in sorted(files.items())}


def _digest_shim(table: dict[bytes, str]) -> types.SimpleNamespace:
    def sha256(data: bytes) -> types.SimpleNamespace:
        real = hashlib.sha256(data).hexdigest()
        return types.SimpleNamespace(hexdigest=lambda: table.get(data, real))
    return types.SimpleNamespace(sha256=sha256)


def _assigned_answer(files: dict[str, bytes], digests: dict[str, str]) -> list[str]:
    real = checker.hashlib
    checker.hashlib = _digest_shim({files[n]: d for n, d in digests.items() if n in files})
    try:
        return bundle_answer(files)
    finally:
        checker.hashlib = real


def _ref(name: str, digest: str) -> dict[str, Any]:
    return {"digest": {"sha256": digest}, "predicateType": checker.TYPE[name]}


def assigned_cases(base: dict[str, bytes]) -> list[dict[str, Any]]:
    """Bundles whose file digests are assigned rather than computed.

    A predecessor names a record by the sha256 of its bytes, so a cycle among
    carried records cannot be written down with real digests. With the digests
    assigned, R2 and RB can name each other, and B4 is reached."""
    records = {name: json.loads(data) for name, data in base.items()}
    label = {name: hashlib.sha256(b"assigned " + name.encode()).hexdigest() for name in base}
    out = []
    shapes = {
        "acyclic": {"r2.json": [("r1.json", checker.R1)],
                    "rb.json": [("r2.json", checker.R2)],
                    "r3.json": [("r1.json", checker.R1), ("r2.json", checker.R2)]},
        "r2-rb-cycle": {"r2.json": [("r1.json", checker.R1), ("rb.json", checker.RB)],
                        "rb.json": [("r2.json", checker.R2)],
                        "r3.json": [("r1.json", checker.R1), ("r2.json", checker.R2)]},
        "rb-self": {"r2.json": [("r1.json", checker.R1)],
                    "rb.json": [("rb.json", checker.RB)],
                    "r3.json": [("r1.json", checker.R1), ("r2.json", checker.R2)]},
        "r3-rb-cycle": {"r2.json": [("r1.json", checker.R1)],
                        "rb.json": [("r3.json", checker.R3)],
                        "r3.json": [("r1.json", checker.R1), ("rb.json", checker.RB)]},
    }
    for shape, refs in shapes.items():
        files: dict[str, bytes | None] = {}
        for name, targets in refs.items():
            record = copy.deepcopy(records[name])
            record["predicate"]["predecessors"] = [_ref(kind, label[t]) for t, kind in targets]
            files[name] = generator.statement_bytes(record)
        judged = _overlay(base, files)
        out.append({"shape": shape, "files": _stored(files), "digests": label,
                    "want": _assigned_answer(judged, label)})
    return out


#: The places a bundle rule reads. An edit anywhere else in a record changes that
#: record's B1 answer and nothing a bundle rule decides, and the record cases hold it.
BUNDLE_PLACES = (("predicateType",), ("predicate", "incident"), ("predicate", "issuedAt"),
                 ("predicate", "predecessors"), ("predicate", "population"),
                 ("predicate", "restoration"))


def _bundle_relevant(path: tuple[Any, ...]) -> bool:
    return any(path[:len(place)] == place for place in BUNDLE_PLACES)


def _edit_cases(index: int, base: dict[str, bytes]) -> list[dict[str, Any]]:
    """Each bundle-rule place in each record of one bundle, edited and relinked."""
    records = {name: json.loads(data) for name, data in base.items()}
    out: list[dict[str, Any]] = []
    seen: set[bytes] = set()
    refused_at: set[tuple[str, tuple[Any, ...]]] = set()
    for name in sorted(records):
        for path, _edit, value in variants(records[name]):
            if not _bundle_relevant(path):
                continue
            relinked = _relinked(records, name, value)
            if relinked is None:
                continue
            files: dict[str, bytes | None] = {
                n: d for n, d in relinked.items() if d != base[n]}
            key = encode(_stored(files))
            if not files or key in seen:
                continue
            seen.add(key)
            want = bundle_answer(_overlay(base, files))
            # A record that fails B1 is the record rule's answer, which the record
            # cases already hold; one of them per place keeps B1 itself checked.
            if want[0] == "reject" and record_answer(relinked[name])[0] == "reject":
                if (name, path) in refused_at:
                    continue
                refused_at.add((name, path))
            out.append({"bundle": index, "files": _stored(files), "want": want})
    return out


def bundle_cases() -> dict[str, Any]:
    entries = _members("bundle")
    bases = [_bundle_files(e) for e in entries]
    out: list[dict[str, Any]] = []
    for index, base in enumerate(bases):
        out += _edit_cases(index, base)
        structural: list[dict[str, bytes | None]] = [
            {name: None} for name in sorted(base)]
        structural += [
            {"r3b.json": base["r3.json"]},
            {name: None for name in base},
            {"extra.json": base["r1.json"]},
            {"r1.json": base["r1.json"] + b"x"},
        ]
        for files in structural:
            out.append({"bundle": index, "files": _stored(files),
                        "want": bundle_answer(_overlay(base, files))})
        for case in assigned_cases(base) if "rb.json" in base else []:
            out.append({"bundle": index, **case})
    return {"bases": [_stored(dict(b)) for b in bases], "cases": out}


@functools.cache
def fixture() -> dict[str, Any]:
    return {"records": record_cases(), "raw": raw_cases(), "bundles": bundle_cases()}


def encoded() -> bytes:
    body = json.dumps(fixture(), sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return gzip.compress(body.encode(), compresslevel=9, mtime=0)


def test_the_go_cases_are_what_python_answers() -> None:
    if os.environ.get("AEV_WRITE_RESTART_RECORDS") == "1":
        FIXTURE.write_bytes(encoded())
    stored = json.loads(gzip.decompress(FIXTURE.read_bytes()))
    assert stored == fixture(), (
        "corpora/testdata/restart-records.json.gz is not what the Python checker answers; "
        "regenerate it with AEV_WRITE_RESTART_RECORDS=1")


def test_the_cases_reach_every_answer() -> None:
    stored = json.loads(gzip.decompress(FIXTURE.read_bytes()))
    record_reasons = {tuple(c["want"]) for c in stored["records"]["cases"]}
    # A rule one edit cannot reach (two parties must both change organization) is
    # reached by its corpus member, which the Go test replays too.
    forced = {(e["predicate"], e["expected"]["reason"]) for e in MANIFEST["vectors"]
              if e["shape"] == "record"}
    unforced = {(u["document"], u["code"]) for u in MANIFEST["unforcedRules"]}
    for name in checker.NAMES:
        for _, code in checker.RULES[name]:
            if (checker.DOCUMENT[name], code) in unforced:
                continue
            assert ("reject", code) in record_reasons or (name, code) in forced, (name, code)
        assert ("accept", checker.ACCEPTED[name]) in record_reasons, name
    bundle_reasons = {tuple(c["want"]) for c in stored["bundles"]["cases"]}
    for _, code in checker.BUNDLE_RULES[1:]:
        assert ("reject", code) in bundle_reasons, code
    assert ("accept", checker.BUNDLE_ACCEPTED) in bundle_reasons
    assert ("unreadable", "") in bundle_reasons
    raw = {tuple(c["want"]) for c in stored["raw"]}
    assert ("reject", "statement-malformed") in raw and len(raw) > 1


def test_the_checker_never_raises_on_a_record() -> None:
    """Every record variant gets a verdict; an exception is a reader defect."""
    for base in record_cases()["bases"]:
        for _path, _edit, value in variants(base):
            checker.check_record_bytes(encode(value))
