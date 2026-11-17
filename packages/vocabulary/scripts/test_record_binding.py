#!/usr/bin/env python3
"""Hold the registry, the validator and the guide to the record_binding section.

Every term starts proposed with no issuer and carries a criticality, a review date, a
definition, a check and a promotion trigger; a term declaring closed values defines each of
them; the guide at docs/record-binding.md names every term and every value; every registered value is
accepted and an unregistered one refused through registry.check_value; the real validator
accepts a crosswalk that maps the section and refuses one that files a term under the wrong
section; and registry.number_in_profile, registry.sequence_numbers and registry.key_history give
the expected value or refusal for each case in their tables. Nothing is restated here.

Exit 0 every case behaves, 1 at least one does not, 2 the check could not run.
"""

from __future__ import annotations

import importlib.util
import json
import os
import sys
import tempfile
from pathlib import Path

import yaml

_ROOT = Path(__file__).resolve().parent.parent
_VALIDATOR = _ROOT / "scripts" / "validate_crosswalks.py"
_VOCAB = _ROOT / "vocabulary.yaml"
_REGISTRY = _ROOT / "registry.py"
_INDEX = _ROOT / "registry.json"
_PAGE = _ROOT / "docs" / "record-binding.md"
SECTION = "record_binding"
PROBE_TERM = "canonicalization"
_EXPECTED_TERMS = {'canonicalization', 'hash_alg', 'sequence_number', 'trajectory_head', 'coverage_boundary', 'signature_coverage', 'key_authority', 'signing_construction', 'key_history'}
_REQUIRED_KEYS = ("criticality", "review_by", "definition", "promotion_trigger", "source_path")


def _load_validator():
    spec = importlib.util.spec_from_file_location("validate_crosswalks", _VALIDATOR)
    if spec is None or spec.loader is None:
        return None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _load_registry():
    spec = importlib.util.spec_from_file_location("vocabulary_registry", _REGISTRY)
    if spec is None or spec.loader is None:
        return None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _check_one_closed_term(registry, index: dict, name: str, values: list) -> list[str]:
    """Each registered value of one closed term is accepted; an unregistered one is refused."""
    failures = []
    try:
        for value in values:
            judged = registry.check_value(index, name, value, None)
            if judged.outcome != registry.OK:
                failures.append(f"{name}: registered value {value!r} was judged {judged.outcome}")
        refused = registry.check_value(index, name, "not-a-registered-value", None)
    except KeyError:
        return [f"{name}: the registry index declares no values for a term that lists them"]
    if refused.outcome != registry.MALFORMED:
        failures.append(f"{name}: an unregistered value was judged {refused.outcome}, "
                        "not malformed")
    return failures


def _check_closed_values(registry, index: dict, section: dict) -> list[str]:
    """Run the closed-value check for every term that lists values."""
    failures = []
    for name, term in section.items():
        values = term.get("values")
        if values is not None:
            failures.extend(_check_one_closed_term(registry, index, name, values))
    return failures


def _crosswalk(section: str) -> dict:
    return {
        "system": SECTION + "-test",
        "system_url": "https://example.invalid/" + SECTION + "-test",
        "crosswalk_version": "0.1.0",
        "vocabulary_version_targeted": "0.10.0",
        section: {PROBE_TERM: {"match": "no_mapping", "notes": "test fixture"}},
    }


def _run(validator, data: dict) -> list[str]:
    known, match_types, evidence_states = validator.load_registry()
    errors: list[str] = []
    warnings: list[str] = []
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / (SECTION + "-test.yaml")
        path.write_text(yaml.safe_dump(data))
        validator.validate_crosswalk_file(
            path, known, match_types, evidence_states, errors, warnings)
    return errors


def _check_fields(name: str, term: dict) -> list[str]:
    """The status, issuer list, check and required keys of one term."""
    failures = []
    if term.get("status") != "proposed":
        failures.append(f"{name}: status must start proposed")
    if term.get("issuers_in_production") != []:
        failures.append(f"{name}: issuers_in_production must be empty")
    for key in ("check", *_REQUIRED_KEYS):
        if not str(term.get(key, "")).strip():
            failures.append(f"{name}: no {key}")
    return failures


def _check_definitions(name: str, term: dict) -> list[str]:
    """A term that lists values defines each of them and nothing else."""
    values = term.get("values")
    if values is None:
        return []
    defined = term.get("value_definitions") or {}
    missing = [v for v in values if not str(defined.get(v, "")).strip()]
    extra = sorted(set(defined) - set(values))
    if missing or extra:
        return [f"{name}: undefined values {missing}, stray definitions {extra}"]
    return []


def _check_guide(name: str, term: dict, page: str) -> list[str]:
    """The guide names the term and every value it lists."""
    failures = [] if f"`{name}`" in page else [f"{name}: the guide never names it"]
    for value in term.get("values") or []:
        if f"`{value}`" not in page:
            failures.append(f"{name}: the guide never names the value `{value}`")
    return failures


def _check_terms(section: dict, page: str) -> list[str]:
    failures = []
    if set(section) != _EXPECTED_TERMS:
        differ = sorted(set(section) ^ _EXPECTED_TERMS)
        failures.append(f"terms {differ} differ from the ones the section carries")
    for name, term in section.items():
        failures.extend(_check_fields(name, term))
        failures.extend(_check_definitions(name, term))
        failures.extend(_check_guide(name, term, page))
    return failures



#: (token, profile, expected value or refusal reason)
_NUMBERS = (
    ("9007199254740991", "jcs_safe_integer_v1", "jcs_safe_integer_v1"),
    ("9007199254740992", "rfc8785", "rfc8785"),
    ("9007199254740992", "jcs_safe_integer_v1", "outside-profile-unsafe-integer"),
    ("-9007199254740992", "jcs_safe_integer_v1", "outside-profile-unsafe-integer"),
    ("9007199254740991.5", "jcs_safe_integer_v1", "outside-profile-unsafe-integer"),
    ("9007199254740991.4", "jcs_safe_integer_v1", "jcs_safe_integer_v1"),
    ("12345678901234567.5", "jcs_safe_integer_v1", "outside-profile-unsafe-integer"),
    ("1.00000000000000001e16", "jcs_safe_integer_v1", "outside-profile-unsafe-integer"),
    ("1.5", "jcs_safe_integer_v1", "jcs_safe_integer_v1"),
    ("1e2", "jcs_safe_integer_v1", "jcs_safe_integer_v1"),
    ("1.5", "jcs_integer_only_v1", "outside-profile-not-an-integer"),
    ("1e2", "jcs_integer_only_v1", "outside-profile-not-an-integer"),
    ("9007199254740991", "jcs_integer_only_v1", "jcs_integer_only_v1"),
    ("9007199254740992", "jcs_integer_only_v1", "outside-profile-integer-range"),
    ("1e400", "rfc8785", "number-not-finite"),
    ("01", "rfc8785", "not-a-json-number"),
    ("1", "cbor_deterministic", "profile-not-a-json-canonicalization"),
    # -0 is an integer token RFC 8785 rewrites to 0; the integer-only profile refuses the rewrite.
    ("-0", "jcs_integer_only_v1", "outside-profile-negative-zero"),
    ("-0", "jcs_safe_integer_v1", "jcs_safe_integer_v1"),
    # A trailing line feed is not part of a number token ($ in a regex would have let it through).
    ("1\n", "rfc8785", "not-a-json-number"),
    ("1\n", "jcs_integer_only_v1", "not-a-json-number"),
)

#: (seq values, expected value or refusal reason)
_SEQUENCES = (
    ([0, 1, 2], "3"),
    ([], "0"),
    ([0, 2], "seq-skips"),
    ([0, 1, 1], "seq-repeats"),
    ([1, 2], "seq-skips"),
    ([0, -1], "seq-not-a-safe-count"),
    ([True], "seq-not-a-safe-count"),
    ([2 ** 53], "seq-not-a-safe-count"),
)

#: (start, seq values, expected value or refusal reason): the start an anchor names is range-checked too
_STARTS = (
    (3, [3, 4], "2"),
    (-5, [], "seq-start-not-a-safe-count"),
    (True, [1], "seq-start-not-a-safe-count"),
    (2 ** 53, [], "seq-start-not-a-safe-count"),
)

_HISTORY = [
    {"key": "k-current", "authorized_from": 100},
    {"key": "k-rotated", "authorized_from": 100, "retired_at": 500},
    {"key": "k-late", "authorized_from": 300},
    {"key": "k-retired-early", "authorized_from": 50, "retired_at": 150},
    {"key": "k-revoked", "authorized_from": 100, "revoked_at": 180},
    {"key": "k-revoked-later", "authorized_from": 100, "revoked_at": 250},
    # A second entry for one key revokes it; a reader of the first entry only reports key_current.
    {"key": "k-dup", "authorized_from": 100},
    {"key": "k-dup", "authorized_from": 100, "revoked_at": 150},
    # Two authorization windows with a gap between them.
    {"key": "k-window", "authorized_from": 0, "retired_at": 100},
    {"key": "k-window", "authorized_from": 300},
    {"key": "k-bad", "authorized_from": True},
    # A window that ends before it starts is a malformed entry, never an empty window.
    {"key": "k-backwards", "authorized_from": 300, "retired_at": 100},
]

#: (key, issued_at, expected value)
_KEYS = (
    ("k-current", 200, "key_current"),
    ("k-rotated", 200, "key_rotated_out"),
    ("k-late", 200, "key_not_authorized_at_issue"),
    ("k-retired-early", 200, "key_not_authorized_at_issue"),
    ("k-revoked", 200, "key_revoked"),
    ("k-revoked", 180, "key_revoked"),
    ("k-revoked-later", 200, "key_rotated_out"),
    ("k-dup", 200, "key_revoked"),
    ("k-window", 200, "key_not_authorized_at_issue"),
    ("k-window", 50, "key_rotated_out"),
    ("k-window", 350, "key_current"),
    ("k-bad", 200, "history-entry-malformed"),
    ("k-backwards", 200, "history-window-ends-before-it-starts"),
    ("k-nobody", 200, "key_unknown"),
)


def _label(derived) -> str:
    return derived.reason if derived.refused else derived.value


_HEAD_OK = {"stream_id": "s1", "digest": "d9", "count": 9}
#: (head, expected value or refusal reason) for stream s1 walked to digest d9 over 9 records
_HEADS = (
    (None, "absent"),
    ({**_HEAD_OK, "witness_verified": True}, "witnessed"),
    ({**_HEAD_OK, "producer_verified": True}, "producer_signed"),
    ({**_HEAD_OK, "witness_verified": True, "stream_id": "s2"}, "head-names-another-stream"),
    ({"digest": "d9", "count": 9, "witness_verified": True}, "head-names-no-stream"),
    ({**_HEAD_OK, "witness_verified": True, "count": 8}, "head-count-differs-from-walk"),
    ({**_HEAD_OK, "witness_verified": True, "count": True}, "head-count-differs-from-walk"),
    ({**_HEAD_OK, "witness_verified": True, "digest": "d8"}, "head-digest-differs-from-walk"),
    ({**_HEAD_OK, "witness_verified": False, "producer_verified": False}, "head-signature-does-not-verify"),
)


def _check_heads(registry) -> list[str]:
    """Each head case gives its value, and the signed bytes carry the stream under the head's own domain."""
    failures = []
    for head, expected in _HEADS:
        got = _label(registry.trajectory_head(head, "s1", "d9", 9))
        if got != expected:
            failures.append(f"trajectory_head({head!r}) gave {got!r}, expected {expected!r}")
    one = registry.trajectory_head_preimage("s1", "d9", 9)
    if not one.startswith(registry.TRAJECTORY_HEAD_DOMAIN) or one == registry.trajectory_head_preimage("s2", "d9", 9):
        failures.append("trajectory_head_preimage does not bind the stream under the head domain")
    # A head whose fields span a line has no signed bytes, so no boolean can make it verify.
    for stream, digest in (("s1\nd9", "d9"), ("s1", "d9\nx")):
        head = {"stream_id": stream, "digest": digest, "count": 9, "witness_verified": True}
        got = _label(registry.trajectory_head(head, stream, digest, 9))
        if got != "head-fields-have-no-signed-bytes":
            failures.append(f"trajectory_head over {stream!r}, {digest!r} gave {got!r}, expected a refusal")
    for bad in (("", "d9", 9), ("s1\nd9", "d9", 9), ("s1", "d9", -1)):
        try:
            registry.trajectory_head_preimage(*bad)
            failures.append(f"trajectory_head_preimage{bad!r} built bytes, expected a refusal")
        except ValueError:
            pass
    return failures


def _check_derivations(registry) -> tuple[list[str], int]:
    """Each reference derivation gives the expected value or refusal for every case."""
    failures = []
    for token, profile, expected in _NUMBERS:
        got = _label(registry.number_in_profile(token, profile))
        if got != expected:
            failures.append(f"number_in_profile({token!r}, {profile!r}) gave {got!r}, expected {expected!r}")
    for seqs, expected in _SEQUENCES:
        got = _label(registry.sequence_numbers(seqs))
        if got != expected:
            failures.append(f"sequence_numbers({seqs!r}) gave {got!r}, expected {expected!r}")
    for start, seqs, expected in _STARTS:
        got = _label(registry.sequence_numbers(seqs, start))
        if got != expected:
            failures.append(f"sequence_numbers({seqs!r}, {start!r}) gave {got!r}, expected {expected!r}")
    for key, issued_at, expected in _KEYS:
        got = _label(registry.key_history(_HISTORY, key, issued_at))
        if got != expected:
            failures.append(f"key_history({key!r}, {issued_at}) gave {got!r}, expected {expected!r}")
    got = _label(registry.key_history([*_HISTORY, "k-current"], "k-current", 200))
    if got != "history-entry-malformed":
        failures.append(f"key_history with an entry that is not an object gave {got!r}, expected a refusal")
    failures.extend(_check_heads(registry))
    return failures, len(_NUMBERS) + len(_SEQUENCES) + len(_STARTS) + len(_KEYS) + len(_HEADS) + 7


def main() -> int:
    os.environ["VALIDATE_CROSSWALKS_OFFLINE"] = "1"
    try:
        vocab = yaml.safe_load(_VOCAB.read_text())
        page = _PAGE.read_text(encoding="utf-8")
        validator = _load_validator()
        registry = _load_registry()
        index = json.loads(_INDEX.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError, ValueError) as exc:
        print(f"test_record_binding: could not run: {exc}", file=sys.stderr)
        return 2
    if validator is None or registry is None:
        print("test_record_binding: could not load the validator or the registry", file=sys.stderr)
        return 2

    section = vocab.get(SECTION)
    if not isinstance(section, dict) or not section:
        print(f"FAIL: vocabulary.yaml has no {SECTION} section")
        return 1
    failures = _check_terms(section, page)
    failures.extend(_check_closed_values(registry, index, section))
    derived, count = _check_derivations(registry)
    failures.extend(derived)
    ok = _run(validator, _crosswalk(SECTION))
    if ok:
        failures.append(f"a valid mapping was refused: {ok}")
    wrong = _run(validator, _crosswalk("evaluation_claim"))
    if not any(SECTION in e for e in wrong):
        failures.append(f"a term filed under the wrong section was not refused by name: {wrong}")

    for f in failures:
        print(f"FAIL: {f}")
    if failures:
        return 1
    print(f"test_record_binding: {len(section)} terms and the guide agree; closed values accept and refuse "
          f"as registered, both validator cases behave, {count} derivation cases agree")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
