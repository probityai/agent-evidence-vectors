"""The corpus regenerates, forces every check in order, and refuses a verifier that compares
digest strings without their profiles, hashes more or less than the profile covers, or
canonicalizes by code point instead of UTF-16 code unit."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _load(name: str, path: Path):  # type: ignore[no-untyped-def]
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


corpus = _load("descriptor_digest_corpus", ROOT / "check_vectors.py")
generator = _load("descriptor_digest_generator", ROOT / "gen_vectors.py")
from agent_evidence_vectors import descriptordigest as reader  # noqa: E402

CHECKS = reader.CHECKS
REFUSED = {c[0]: c[3] for c in generator.cases() if c[2] == "refused"}
GAPS = {c[0]: c[3] for c in generator.cases() if c[2] == "gap"}
MATCHES = [c[0] for c in generator.cases() if c[2] == "match"]
CONTRADICTED = [c[0] for c in generator.cases() if c[2] == "contradicted"]


def _records() -> dict[str, dict]:  # type: ignore[type-arg]
    return {
        p.parent.name: json.loads(p.read_text(encoding="utf-8"))
        for p in (ROOT / "cases").glob("*/record.json")
    }


def _failed(errors: list[str]) -> set[str]:
    """Names with a wrong decision; a declared-fields mismatch is a separate error."""
    return {e.split(":", 1)[0] for e in errors if "declared retained" not in e}


def _script(tmp_path: Path, body: str) -> str:
    script = tmp_path / "verifier.py"
    script.write_text(
        "import json, sys\n"
        f"sys.path.insert(0, {str(ROOT.parents[1] / 'packaging')!r})\n"
        "from agent_evidence_vectors import descriptordigest as r\n"
        "record = json.load(open(sys.argv[1]))\n" + body,
        encoding="ascii",
    )
    return f"{sys.executable} {script}"


def test_regeneration_is_byte_identical(tmp_path: Path) -> None:
    generator.generate(tmp_path)
    committed = {
        p.relative_to(ROOT): p.read_bytes()
        for p in [ROOT / "MANIFEST.json", *(ROOT / "cases").rglob("*")]
        if p.is_file()
    }
    regenerated = {
        p.relative_to(tmp_path): p.read_bytes() for p in tmp_path.rglob("*") if p.is_file()
    }
    assert regenerated == committed


def test_reference_reader_agrees_with_every_case() -> None:
    answered, errors = corpus.check()
    assert errors == []
    assert answered == len(generator.cases())


def test_counts_come_from_the_manifest() -> None:
    manifest = json.loads((ROOT / "MANIFEST.json").read_text(encoding="utf-8"))
    assert manifest["counts"] == {
        "contradicted": len(CONTRADICTED),
        "gap": len(GAPS),
        "match": len(MATCHES),
        "refused": len(REFUSED),
    }
    assert manifest["profiles"] == list(reader.PROFILES)


def test_every_member_names_its_source_and_its_sentence() -> None:
    manifest = json.loads((ROOT / "MANIFEST.json").read_text(encoding="utf-8"))
    for entry in manifest["vectors"]:
        assert entry["source"] and entry["rule"] and entry["anchor"]["quote"], entry["id"]


def test_recorded_members_carry_the_declarations_unedited() -> None:
    source = json.loads(generator.SOURCE_FILE.read_text(encoding="utf-8"))
    before = {t["name"]: t for t in source["toolsets"]["before"]["tools"]}
    after = {t["name"]: t for t in source["toolsets"]["after"]["tools"]}
    records = _records()
    rewrite = records["contradicted-recorded-description-rewrite"]
    twin = records["match-recorded-tool-unchanged"]
    assert rewrite["pin"]["descriptor"] == before["get_shop_services"]
    assert rewrite["observation"]["descriptor"] == after["get_shop_services"]
    assert twin["pin"]["descriptor"] == twin["observation"]["descriptor"]
    modified = sorted(n for n in before if before[n] != after[n])
    assert modified == ["get_shop_services", "search_availability", "search_shops", "start_booking"]


def test_set_digest_recipe_reproduces_the_recorded_digests() -> None:
    source = json.loads(generator.SOURCE_FILE.read_text(encoding="utf-8"))
    import base64
    import hashlib

    for which in ("before", "after"):
        listed = source["toolsets"][which]
        raw = hashlib.sha256(reader.jcs(listed["tools"])).digest()
        assert "sha256-" + base64.b64encode(raw).decode("ascii") == listed["digest"]
    assert source["change"]["fromToolSetDigest"] == source["toolsets"]["before"]["digest"]
    assert source["change"]["toToolSetDigest"] == source["toolsets"]["after"]["digest"]


def test_rfc8785_key_order_is_by_utf16_code_unit() -> None:
    # The sorting example of RFC 8785 section 3.2.3.
    value = {
        "€": "Euro Sign",
        "\r": "Carriage Return",
        "דּ": "Hebrew Letter Dalet With Dagesh",
        "1": "One",
        "\U0001f600": "Emoji: Grinning Face",
        "\u0080": "Control",
        "ö": "Latin Small Letter O With Diaeresis",
    }
    keys = list(json.loads(reader.jcs(value).decode("utf-8")))
    assert keys == ["\r", "1", "\u0080", "ö", "€", "\U0001f600", "דּ"]


@pytest.mark.parametrize("name", sorted(REFUSED))
def test_each_refusal_fails_exactly_its_named_check(name: str) -> None:
    record, reason = _records()[name], REFUSED[name]
    assert reader._first_failure(record, frozenset()) == reason
    assert reader._first_failure(record, frozenset(CHECKS[CHECKS.index(reason) :])) is None


@pytest.mark.parametrize("name", CHECKS)
def test_every_check_is_forced_by_some_case(name: str) -> None:
    _, errors = corpus.check(skip=frozenset({name}))
    assert errors, f"switching off {name} changed no verdict"


def test_verifier_that_compares_digest_strings_without_profiles_fails_every_gap(
    tmp_path: Path,
) -> None:
    body = (
        "same = record['pin']['digest'] == record['observation']['digest']\n"
        "word, code = ('match', 0) if same else ('contradicted', 1)\n"
        "print(json.dumps({'decision': word, 'reason': 'x'}))\nsys.exit(code)\n"
    )
    _, errors = corpus.check(_script(tmp_path, body))
    assert set(GAPS) <= _failed(errors)


def test_verifier_that_ignores_profile_equality_fails_the_profile_gaps(tmp_path: Path) -> None:
    body = (
        "pin, obs = record['pin'], record['observation']\n"
        "ok = r._first_failure(record, frozenset()) is None\n"
        "if not ok:\n"
        "    print(json.dumps(r.judge(record)))\n    sys.exit(3)\n"
        "same = pin['digest'] == obs['digest']\n"
        "word, code = ('match', 0) if same else ('contradicted', 1)\n"
        "print(json.dumps({'decision': word, 'reason': 'x'}))\nsys.exit(code)\n"
    )
    _, errors = corpus.check(_script(tmp_path, body))
    assert {
        "gap-same-descriptor-two-profiles",
        "gap-absent-description-two-rules",
        "gap-profiles-differ-digests-coincide",
        "gap-pin-without-profile",
    } <= _failed(errors)


def test_verifier_that_hashes_the_whole_descriptor_fails_the_coverage_controls(
    tmp_path: Path,
) -> None:
    body = (
        "pin, obs = record['pin'], record['observation']\n"
        "same = r.digest(pin['descriptor'], r.WHOLE) == r.digest(obs['descriptor'], r.WHOLE)\n"
        "word, code = ('match', 0) if same else ('contradicted', 1)\n"
        "print(json.dumps({'decision': word, 'reason': 'x'}))\nsys.exit(code)\n"
    )
    _, errors = corpus.check(_script(tmp_path, body))
    assert "match-annotation-change-outside-the-profile" in _failed(errors)


def test_canonicalizer_that_sorts_by_code_point_fails_the_utf16_control(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import json as _json

    def by_code_point(node):  # type: ignore[no-untyped-def]
        if isinstance(node, dict):
            members = sorted(node.items(), key=lambda pair: pair[0])
            body = ",".join(
                f"{_json.dumps(k, ensure_ascii=False)}:{by_code_point(v)}" for k, v in members
            )
            return "{" + body + "}"
        if isinstance(node, list):
            return "[" + ",".join(by_code_point(i) for i in node) + "]"
        return _json.dumps(node, ensure_ascii=False, separators=(",", ":"))

    monkeypatch.setattr(reader, "_encode", by_code_point)
    _, errors = corpus.check()
    assert "match-utf16-key-order" in _failed(errors)


def test_verifier_that_refuses_everything_fails_the_controls(tmp_path: Path) -> None:
    script = tmp_path / "refuse.py"
    script.write_text(
        'import json, sys\nprint(json.dumps({"decision": "refused", '
        '"reason": "contract_id_missing"}))\nsys.exit(3)\n',
        encoding="ascii",
    )
    _, errors = corpus.check(f"{sys.executable} {script}")
    assert (set(MATCHES) | set(CONTRADICTED) | set(GAPS)) <= _failed(errors)


def test_verifier_that_accepts_everything_fails_the_rest(tmp_path: Path) -> None:
    script = tmp_path / "accept.py"
    script.write_text(
        'import json, sys\nprint(json.dumps({"decision": "match", '
        '"reason": "descriptor_unchanged"}))\n',
        encoding="ascii",
    )
    _, errors = corpus.check(f"{sys.executable} {script}")
    assert (set(CONTRADICTED) | set(GAPS) | set(REFUSED)) <= _failed(errors)


def test_missing_verifier_does_not_count_as_answered(tmp_path: Path) -> None:
    answered, errors = corpus.check(str(tmp_path / "no-such-verifier"))
    assert answered == 0 and errors
