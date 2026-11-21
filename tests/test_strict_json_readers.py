"""Every reader refuses a record that only a lenient JSON parser can read.

Python's ``json`` module admits ``NaN``, ``Infinity`` and ``-Infinity``, turns ``1e999`` into
``inf``, and keeps the last of two members with one name. Each is a record that two readers
can read two ways: ``NaN > cap`` is ``False``, so a ``NaN`` amount passes every cap; and a
reader that keeps the first repeated member judges a record the one that keeps the last never
saw. A reader refuses all of them, so no hostile spelling of an accepted case is accepted.

The reader tests take every accepted member of every corpus whose reader judges one case file,
and change one thing at a time in a copy of it: a member repeated ahead of the original (a
keep-the-last reader sees the original unchanged), a non-finite constant added beside the
members, and the first number in the file made ``NaN``. Each copy must not be accepted.
"""

from __future__ import annotations

import ast
import importlib
import json
import re
import shutil
import sys
from pathlib import Path
from types import ModuleType

import pytest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "packaging"))
import run_vectors
from agent_evidence_vectors import strictjson

# Readers whose ``verify(path)`` judges one member file of a corpus with a manifest of
# ``{"id", "path", "files", "expected"}`` entries. The other readers are covered below by
# their own entry point.
CASE_READERS = (
    "agenticprocess", "aggregateaccounting", "anchoredchain", "approvalbinding",
    "authoritydispatch", "badgevc", "changeadmission", "chunkedexport",
    "completionconfirmation", "connectorscope", "containmentjournal", "convertedargs",
    "credreach", "decisionclient", "delegatorright", "dispatchfence", "evidencecell", "evidencestate",
    "gradefloor", "identitybinding", "monitorcoverage", "openweight", "paymentmandate",
    "propagationstep", "receiptchainend", "refusalreason", "signaturecoverage",
    "traceanchor", "uncertaineffect",
)
ACCEPTING = {"accepted", "allow", "verified", "supported", "anchored", "conformant", "exempt"}
HOSTILE = ("repeated-member", "non-finite-member", "first-number-nan")


def _accepting(module: ModuleType) -> set[str]:
    exits = getattr(module, "EXIT_FOR", None)
    if isinstance(exits, dict):
        return {decision for decision, code in exits.items() if code == 0}
    return ACCEPTING


def _answer(module: ModuleType, path: Path) -> dict:
    """What the reader says of one file, or nothing when this file is not the kind it reads."""
    try:
        answer = module.verify(path)
    except Exception:  # noqa: BLE001 -- not the file this reader is handed
        return {}
    return answer if isinstance(answer, dict) else {}


def _accepted_member(module: ModuleType) -> tuple[Path, str]:
    """The first accepted member's directory and the file the reader is handed."""
    manifest = json.loads((Path(module.ROOT) / "MANIFEST.json").read_text(encoding="utf-8"))
    accepting = _accepting(module)
    for entry in manifest["vectors"]:
        if entry.get("expected", {}).get("decision") not in accepting:
            continue
        directory = Path(module.ROOT) / entry["path"]
        for name in sorted(entry.get("files") or {}):
            if not name.endswith(".json"):
                continue
            answer = _answer(module, directory / name)
            if {key: answer.get(key) for key in entry["expected"]} == entry["expected"]:
                return directory, name
    raise AssertionError(f"{module.__name__}: no accepted member found")


def _first_key(text: str) -> str:
    match = re.match(r'\s*\{\s*("(?:[^"\\]|\\.)*")\s*:', text)
    assert match, "member file is not a JSON object"
    return match.group(1)


def _hostile(text: str, kind: str) -> str | None:
    """One hostile spelling of a member file, or None where the shape has no place in it."""
    brace = text.index("{") + 1
    if kind == "repeated-member":
        return f"{text[:brace]}{_first_key(text)}: null, {text[brace:]}"
    if kind == "non-finite-member":
        return f'{text[:brace]}"strictJsonProbe": NaN, {text[brace:]}'
    number = re.search(r'(?<=[:\[,])\s*-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?(?=\s*[,}\]])', text)
    if number is None:
        return None
    return f"{text[: number.start()]} NaN{text[number.end():]}"


def _judged(module: ModuleType, path: Path) -> str:
    try:
        answer = module.verify(path)
    except ValueError as exc:  # NotStrictJson is a ValueError
        return f"refused ({type(exc).__name__})"
    return str(answer.get("decision"))


@pytest.mark.parametrize("kind", HOSTILE)
@pytest.mark.parametrize("name", CASE_READERS)
def test_a_case_reader_accepts_no_lenient_spelling(name: str, kind: str, tmp_path: Path) -> None:
    module = importlib.import_module(f"agent_evidence_vectors.{name}")
    directory, handed = _accepted_member(module)
    copy = tmp_path / directory.name
    shutil.copytree(directory, copy)
    assert _judged(module, copy / handed) in _accepting(module), "control copy not accepted"
    accepted = []
    for member in sorted(copy.rglob("*.json")):
        original = member.read_text(encoding="utf-8")
        if not original.lstrip().startswith("{"):
            continue
        hostile = _hostile(original, kind)
        if hostile is None:
            continue
        member.write_text(hostile, encoding="utf-8")
        decision = _judged(module, copy / handed)
        member.write_text(original, encoding="utf-8")
        if decision in _accepting(module):
            accepted.append(member.relative_to(copy).as_posix())
    assert accepted == [], f"{name} accepted a {kind} spelling of {accepted}"


@pytest.mark.parametrize(
    "text",
    ['{"a": NaN}', '{"a": Infinity}', '{"a": -Infinity}', '{"a": 1e999}', '[-1e999]',
     '{"a": 1, "a": 2}', '{"a": {"b": 1, "b": 1}}', '[{"x": [], "x": []}]', '{"a": 1} x'],
)
def test_strictjson_refuses_what_json_lets_through(text: str) -> None:
    with pytest.raises(strictjson.NotStrictJson):
        strictjson.loads(text)
    with pytest.raises(json.JSONDecodeError):  # every existing malformed handler catches it
        strictjson.loads(text.encode())


def test_strictjson_reads_strict_json_as_json_does() -> None:
    text = '{"a": [1, 2.5, -0.0, 1e300, "NaN", true, null], "b": {"a": 1}}'
    assert strictjson.loads(text) == json.loads(text)


@pytest.mark.parametrize(
    "raw",
    [b'{"a": NaN}', b'{"a": Infinity}', b'{"a": -Infinity}', b'{"a": 1, "a": 2}'],
)
def test_the_rail_parser_refuses_non_finite_and_repeated_members(raw: bytes) -> None:
    with pytest.raises(run_vectors.IJsonError):
        run_vectors.parse_json_value(raw)


def _module_sources() -> list[Path]:
    package = REPO / "packaging" / "agent_evidence_vectors"
    sources = [p for p in package.rglob("*.py") if p.name != "strictjson.py"]
    sources.append(REPO / "packaging" / "run_vectors.py")
    sources.extend(sorted((REPO / "corpora").glob("*/check_vectors.py")))
    return sources


# A json.loads that keeps its own call is strict when it passes both refusal hooks. These two
# do not, and each says why.
OWN_PROFILE = {
    # The A2A JCS corpus reads NaN and Infinity and refuses them at canonicalization, under
    # the reason its number-serialization vectors (A5-REJECT-016 to 018) expect.
    ("packaging/agent_evidence_vectors/a2ajcs.py", "parse"),
    # A detector, not a reader: it reports whether the payload repeats a member, which the
    # signature-coverage rules then refuse under their own reason.
    ("packaging/agent_evidence_vectors/signaturecoverage.py", "_repeated_member"),
}


def _is_json_parse(node: ast.AST) -> bool:
    return (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name) and node.func.value.id == "json"
            and node.func.attr in ("load", "loads"))


def _lenient_calls(source: Path) -> list[str]:
    tree = ast.parse(source.read_text(encoding="utf-8"))
    rel = source.relative_to(REPO).as_posix()
    owner: dict[ast.AST, str] = {}
    functions = [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)]
    for function in sorted(functions, key=lambda f: f.end_lineno - f.lineno, reverse=True):
        for node in ast.walk(function):  # innermost function written last, so it wins
            owner[node] = function.name
    found = []
    for node in ast.walk(tree):
        if not _is_json_parse(node):
            continue
        assert isinstance(node, ast.Call)
        if node.args and ast.unparse(node.args[0]).startswith("json.dumps("):
            continue  # a deep copy of our own value
        name = owner.get(node, "<module>")
        hooks = {k.arg for k in node.keywords}
        if {"object_pairs_hook", "parse_constant"} <= hooks or (rel, name) in OWN_PROFILE:
            continue
        found.append(f"{rel}:{node.lineno} in {name}")
    return found


def test_no_reader_parses_with_the_lenient_json_module() -> None:
    found = [site for source in _module_sources() for site in _lenient_calls(source)]
    assert found == [], "\n".join(found)
