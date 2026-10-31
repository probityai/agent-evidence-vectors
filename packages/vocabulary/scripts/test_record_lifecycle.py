#!/usr/bin/env python3
"""Hold the registry and the validator to the record_lifecycle section.

`revision_reason` is a closed code a consumer counts by, so the codes are only
useful if the registry defines each one and the validator accepts a crosswalk
that maps the term. This reads the codes from vocabulary.yaml, requires a
definition for every code and no definition for a code that is not listed, and
runs the real validator over one crosswalk that maps the term and one that files
it under the wrong section. Nothing is restated here.

Exit 0 every case behaves, 1 at least one does not, 2 the check could not run.
"""

from __future__ import annotations

import importlib.util
import os
import sys
import tempfile
from pathlib import Path

import yaml

_ROOT = Path(__file__).resolve().parent.parent
_VALIDATOR = _ROOT / "scripts" / "validate_crosswalks.py"
_VOCAB = _ROOT / "vocabulary.yaml"


def _load_validator():
    spec = importlib.util.spec_from_file_location("validate_crosswalks", _VALIDATOR)
    if spec is None or spec.loader is None:
        return None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _crosswalk(section: str) -> dict:
    return {
        "system": "record-lifecycle-test",
        "system_url": "https://example.invalid/record-lifecycle-test",
        "crosswalk_version": "0.1.0",
        "vocabulary_version_targeted": "0.4.0",
        section: {"revision_reason": {"match": "no_mapping", "notes": "test fixture"}},
    }


def _run(validator, data: dict) -> list[str]:
    known, match_types, evidence_states = validator.load_registry()
    errors: list[str] = []
    warnings: list[str] = []
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "record-lifecycle-test.yaml"
        path.write_text(yaml.safe_dump(data))
        validator.validate_crosswalk_file(path, known, match_types, evidence_states, errors, warnings)
    return errors


def main() -> int:
    os.environ["VALIDATE_CROSSWALKS_OFFLINE"] = "1"
    try:
        vocab = yaml.safe_load(_VOCAB.read_text())
        validator = _load_validator()
    except (OSError, yaml.YAMLError) as exc:
        print(f"test_record_lifecycle: could not run: {exc}", file=sys.stderr)
        return 2
    if validator is None:
        print("test_record_lifecycle: could not load the validator", file=sys.stderr)
        return 2

    failures = []
    term = (vocab.get("record_lifecycle") or {}).get("revision_reason")
    if not isinstance(term, dict):
        print("FAIL: vocabulary.yaml has no record_lifecycle.revision_reason term")
        return 1
    codes = term.get("values") or []
    defined = term.get("value_definitions") or {}
    if len(codes) < 2 or len(set(codes)) != len(codes):
        failures.append(f"codes must be at least two and distinct, got {codes}")
    missing = [c for c in codes if not str(defined.get(c, "")).strip()]
    extra = sorted(set(defined) - set(codes))
    if missing:
        failures.append(f"codes with no definition: {missing}")
    if extra:
        failures.append(f"definitions for codes that are not listed: {extra}")
    if "declaration_added" not in codes:
        failures.append("the first code, declaration_added, is missing")
    shape = term.get("entry_shape") or {}
    if "reason_code" not in (shape.get("required") or []):
        failures.append("entry_shape.required must name reason_code")

    ok = _run(validator, _crosswalk("record_lifecycle"))
    if ok:
        failures.append(f"a valid mapping was refused: {ok}")
    wrong = _run(validator, _crosswalk("posture_and_coverage"))
    if not any("record_lifecycle" in e for e in wrong):
        failures.append(f"a term filed under the wrong section was not refused by name: {wrong}")

    for f in failures:
        print(f"FAIL: {f}")
    if failures:
        return 1
    print(f"test_record_lifecycle: {len(codes)} codes defined; both validator cases behave")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
