#!/usr/bin/env python3
"""Hold the validator to its promise that every file in crosswalk/ is read.

The validator's docstring says a file it does not recognize fails loudly. Until
0.3.0 it read `*.yaml` only, so the first filing's JSON and Markdown sidecars sat in
the directory unread, and the template targeted a registry version two releases
old. This builds a directory per case in a temporary location, points the real
validator's directory functions at it, and requires each wrong layout to be refused
by name and the right one to pass. No rule is reimplemented here.

Exit 0 every case behaves, 1 at least one does not, 2 the check could not run.
"""

from __future__ import annotations

import importlib.util
import shutil
import sys
import tempfile
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_VALIDATOR = _ROOT / "scripts" / "validate_crosswalks.py"
_REAL = _ROOT / "crosswalk"

#: (name, files to write as {name: text}, text the refusal must contain or None to pass)
_CASES = (
    ("a filing with its sidecars", {}, None),
    ("an unrelated file", {"notes.txt": "hello\n"}, "notes.txt"),
    ("a sidecar with no crosswalk", {"orphan-mapping.json": "{}\n"}, "orphan-mapping.json"),
    ("a JSON sidecar that does not parse", {"aee-e2-broken.json": "{not json\n"}, "not valid JSON"),
    ("an empty sidecar", {"aee-e2-empty.md": "\n"}, "sidecar is empty"),
)


def _load():
    spec = importlib.util.spec_from_file_location("validate_crosswalks", _VALIDATOR)
    if spec is None or spec.loader is None:
        return None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _errors(validator, directory: Path) -> list[str]:
    errors: list[str] = []
    _crosswalks, sidecars = validator.classify_directory(directory, errors)
    for path in sidecars:
        validator.check_sidecar(path, errors)
    validator.check_template_version(directory / "TEMPLATE.yaml", errors)
    return errors


def main() -> int:
    validator = _load()
    if validator is None:
        print(f"test_crosswalk_directory: REFUSED -- {_VALIDATOR} could not be loaded; "
              "nothing was checked.", file=sys.stderr)
        return 2
    failures: list[str] = []
    for name, extra, expected in _CASES:
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp) / "crosswalk"
            shutil.copytree(_REAL, directory)
            for filename, text in extra.items():
                (directory / filename).write_text(text, encoding="utf-8")
            errors = _errors(validator, directory)
        if expected is None and errors:
            failures.append(f"{name}: refused, and must pass: {errors}")
        elif expected is not None and not any(expected in e for e in errors):
            failures.append(f"{name}: not refused with {expected!r}: {errors}")

    with tempfile.TemporaryDirectory() as tmp:
        directory = Path(tmp) / "crosswalk"
        shutil.copytree(_REAL, directory)
        template = directory / "TEMPLATE.yaml"
        text = template.read_text(encoding="utf-8")
        current = f'vocabulary_version_targeted: "{validator.yaml.safe_load(_ROOT.joinpath("vocabulary.yaml").read_text())["meta"]["version"]}"'
        if current not in text:
            failures.append("TEMPLATE.yaml does not target the current vocabulary version")
        template.write_text(text.replace(current, 'vocabulary_version_targeted: "0.1.1"'), encoding="utf-8")
        if not any("targets vocabulary version 0.1.1" in e for e in _errors(validator, directory)):
            failures.append("a template targeting an old version was not refused")

    for line in failures:
        print(f"FAIL: {line}", file=sys.stderr)
    checked = len(_CASES) + 2
    print(f"test_crosswalk_directory: {checked - len(failures)} of {checked} checks behaved.")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
