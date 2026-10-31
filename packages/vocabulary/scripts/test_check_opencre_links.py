#!/usr/bin/env python3
"""Hold check_opencre_links.py to refusing every link OpenCRE should not import.

Each case below is a registry and a docs page that differ from a valid pair in
one way, with the words the refusal must contain. The valid pair must pass, and
the repository's own vocabulary.yaml and docs/OPENCRE.md must pass, so a check
that refuses everything fails here as surely as one that refuses nothing.

Exit 0 every case behaves, 1 at least one does not, 2 the check could not run.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_CHECKER = _ROOT / "scripts" / "check_opencre_links.py"

_LINK = """    opencre:
      - cre: https://www.opencre.org/cre/515-021
        match: structural
        basis: "Records the network isolation the artifact ran inside."
"""

_REGISTRY = """# a registry fixture
meta:
  version: "0.0.0"
posture_and_coverage:
  containment_posture:
    status: proposed
    definition: >
      The network posture.
{link}crosswalk_match_types:
  exact: "a"
  structural: "b"
  partial: "c"
  non_equivalent_similar_label: "d"
  no_mapping: "e"
"""

_DOC = """| term | CRE | match | basis |
| --- | --- | --- | --- |
| `posture_and_coverage.containment_posture` | [515-021](https://www.opencre.org/cre/515-021) Sandbox | structural | Records the network isolation the artifact ran inside. |
"""

_SECOND_TERM = """  does_not_assert:
    status: proposed
"""

_UNLINKED = "| `posture_and_coverage.does_not_assert` | no requirement fits |\n"


def _registry(link: str = _LINK, extra: str = "") -> str:
    return _REGISTRY.format(link=link) + extra


#: (name, registry text, docs text, words the refusal must contain)
_CASES = (
    ("bare id", _registry(_LINK.replace("https://www.opencre.org/cre/515-021", '"515-021"')), _DOC, "not a full"),
    ("no www", _registry(_LINK.replace("https://www.", "https://")), _DOC, "not a full"),
    ("plain http", _registry(_LINK.replace("https://", "http://")), _DOC, "not a full"),
    ("trailing path", _registry(_LINK.replace("515-021", "515-021/extra")), _DOC, "not a full"),
    ("short id", _registry(_LINK.replace("515-021", "51-021")), _DOC, "not a full"),
    ("missing basis", _registry(_LINK.replace('        basis: "Records the network isolation the artifact ran inside."\n', "")),
     _DOC, "missing ['basis']"),
    ("extra key", _registry(_LINK + "        note: x\n"), _DOC, "unexpected ['note']"),
    ("empty basis", _registry(_LINK.replace('"Records the network isolation the artifact ran inside."', '""')),
     _DOC, "one non-empty line"),
    ("no_mapping is not a link", _registry(_LINK.replace("match: structural", "match: no_mapping")), _DOC,
     "is not one of"),
    ("not a list", _registry("    opencre: https://www.opencre.org/cre/515-021\n"), _DOC, "non-empty list"),
    ("empty list", _registry("    opencre: []\n"), _DOC, "non-empty list"),
    ("item is a string", _registry("    opencre:\n      - https://www.opencre.org/cre/515-021\n"), _DOC,
     "must be a mapping"),
    ("duplicate", _registry(_LINK + _LINK.split("\n", 1)[1]), _DOC, "linked twice"),
    ("url in a comment", _registry(extra="# see https://www.opencre.org/cre/123-456\n"), _DOC,
     "opencre.org/cre/123-456 appears 1 time(s) in the text and is declared 0"),
    ("url in a definition", _registry().replace("The network posture.", "The posture, see opencre.org/cre/515-021."),
     _DOC, "appears 2 time(s) in the text and is declared 1"),
    ("opencre under meta", _registry().replace('  version: "0.0.0"\n',
                                               '  version: "0.0.0"\n  opencre: []\n'), _DOC,
     "belongs only on a term"),
    ("doc row missing", _registry(), "| term | CRE | match | basis |\n", "has no row for"),
    ("doc row undeclared", _registry(), _DOC.replace("515-021", "112-648"), "does not declare"),
    ("doc row wrong url", _registry(), _DOC.replace("(https://www.opencre.org/cre/515-021)",
                                                     "(https://opencre.org/cre/515-021)"), "links https://opencre.org"),
    ("doc match differs", _registry(), _DOC.replace("| structural |", "| exact |"), "does not declare"),
    ("doc basis differs", _registry(), _DOC.replace("ran inside.", "ran in."), "with a basis vocabulary.yaml"),
    ("unlinked term not explained", _registry().replace("crosswalk_match_types:", _SECOND_TERM + "crosswalk_match_types:"),
     _DOC, "does not say why posture_and_coverage.does_not_assert has no CRE"),
    ("linked term listed as unlinked", _registry(),
     _DOC + "| `posture_and_coverage.containment_posture` | no requirement fits |\n", "lists posture_and_coverage"),
)


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        return None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main() -> int:
    checker = _load(_CHECKER, "check_opencre_links")
    sections = checker._term_sections() if checker else None
    if not sections:
        print("test_check_opencre_links: REFUSED -- the checker or the validator's term sections "
              "could not be loaded; nothing was checked.", file=sys.stderr)
        return 2

    failures: list[str] = []
    errors, links = checker.check(_registry(), _DOC, sections)
    expected = [("posture_and_coverage.containment_posture", "515-021", "structural",
                 "Records the network isolation the artifact ran inside.")]
    if errors or links != expected:
        failures.append(f"the valid fixture was not accepted as one link: errors={errors}, links={links}")

    with_second = _registry().replace("crosswalk_match_types:", _SECOND_TERM + "crosswalk_match_types:")
    errors, _ = checker.check(with_second, _DOC + _UNLINKED, sections)
    if errors:
        failures.append(f"an unlinked term the page explains was refused: {errors}")

    for name, registry, doc, words in _CASES:
        errors, _ = checker.check(registry, doc, sections)
        if not any(words in error for error in errors):
            failures.append(f"{name}: expected a refusal containing {words!r}, got {errors}")

    real_errors, real_links = checker.check(
        (_ROOT / "vocabulary.yaml").read_text(encoding="utf-8"),
        (_ROOT / "docs" / "OPENCRE.md").read_text(encoding="utf-8"),
        sections,
    )
    if real_errors or not real_links:
        failures.append(f"the repository's own registry and docs page did not pass: {real_errors or 'no links'}")

    for line in failures:
        print(f"FAIL: {line}", file=sys.stderr)
    print(f"test_check_opencre_links: {len(_CASES) + 3 - len(failures)} of {len(_CASES) + 3} cases behave.")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
