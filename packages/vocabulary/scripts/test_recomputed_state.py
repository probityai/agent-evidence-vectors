#!/usr/bin/env python3
"""Hold the validator to the registry's definition of `evidence: recomputed`.

The registry defines recomputed as agreement with the reference verdict on EVERY
accepted member of one pinned corpus revision, stated as a count over a named
corpus. A definition that is a count is only as good as the check on the count,
so this runs the real validator over one valid claim and one claim per way the
count or the corpus can be wrong, and requires each refusal to name the field
that is wrong. No rule is reimplemented here: the cases go through
`validate_crosswalk_file` exactly as CI's run does.

It also requires the state to be READ from vocabulary.yaml. The validator takes
its closed vocabularies from the registry and restates none of them, so a test
that only exercised the validator could pass while the registry lacked the state
the validator was checking.

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

_DIGEST = "8b035678def9e5ac00ba761b8c640e4412c57163134afb9d2c1a90f49d573a52"

_VALID_RESULT = {
    "match": "exact",
    "evidence": "recomputed",
    "source_path": "https://example.invalid/reports/first-run.json",
    "corpus_digest": _DIGEST,
    "accepted_agreed": 61,
    "accepted_total": 61,
}

#: (name, the change to the valid claim, the text the refusal must contain).
#: None as a change value deletes the key.
_REFUSALS = (
    ("no corpus_digest", {"corpus_digest": None}, "corpus_digest"),
    ("no accepted_agreed", {"accepted_agreed": None}, "accepted_agreed"),
    ("no accepted_total", {"accepted_total": None}, "accepted_total"),
    ("partial agreement", {"accepted_agreed": 60}, "60 of 61"),
    ("agreement over nothing", {"accepted_agreed": 0, "accepted_total": 0}, "accepted_total=0"),
    ("digest not hex", {"corpus_digest": "sha256:" + _DIGEST[:57]}, "corpus_digest"),
    ("digest upper case", {"corpus_digest": _DIGEST.upper()}, "corpus_digest"),
    ("count as a string", {"accepted_agreed": "61"}, "whole numbers"),
    ("count as a boolean", {"accepted_total": True, "accepted_agreed": True}, "whole numbers"),
)


def _load_validator():
    spec = importlib.util.spec_from_file_location("validate_crosswalks", _VALIDATOR)
    if spec is None or spec.loader is None:
        return None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _crosswalk(result: dict) -> dict:
    return {
        "system": "recomputed-state-test",
        "system_url": "https://example.invalid/recomputed-state-test",
        "crosswalk_version": "0.1.0",
        "vocabulary_version_targeted": "0.3.0",
        "outcome_lattice": {"result": result},
    }


def _errors(validator, registry, result: dict) -> list[str]:
    known_terms, match_types, evidence_states = registry
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "recomputed-state-test.yaml"
        path.write_text(yaml.safe_dump(_crosswalk(result)), encoding="utf-8")
        errors: list[str] = []
        warnings: list[str] = []
        validator.validate_crosswalk_file(
            path, known_terms, match_types, evidence_states, errors, warnings
        )
    return errors


def _changed(change: dict) -> dict:
    result = dict(_VALID_RESULT)
    for key, value in change.items():
        if value is None:
            result.pop(key, None)
        else:
            result[key] = value
    return result


def main() -> int:
    # The valid claim cites an https path; no case here may reach the network.
    os.environ["VALIDATE_CROSSWALKS_OFFLINE"] = "1"
    validator = _load_validator()
    if validator is None:
        print(f"test_recomputed_state: REFUSED -- {_VALIDATOR} could not be loaded; "
              "nothing was checked.", file=sys.stderr)
        return 2
    registry = validator.load_registry()
    failures: list[str] = []

    if "recomputed" not in registry[2]:
        failures.append("vocabulary.yaml does not register recomputed under "
                        "crosswalk_evidence_states, so no filer can declare it")

    errors = _errors(validator, registry, _VALID_RESULT)
    if errors:
        failures.append(f"the valid recomputed claim was refused: {errors}")

    for name, change, expected in _REFUSALS:
        errors = _errors(validator, registry, _changed(change))
        if not errors:
            failures.append(f"{name}: accepted, and must be refused")
        elif not any(expected in e for e in errors):
            failures.append(f"{name}: refused without naming '{expected}': {errors}")

    for line in failures:
        print(f"FAIL: {line}", file=sys.stderr)
    checked = 2 + len(_REFUSALS)
    print(f"test_recomputed_state: {checked - len(failures)} of {checked} checks behaved.")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
