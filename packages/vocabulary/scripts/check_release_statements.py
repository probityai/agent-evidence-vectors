#!/usr/bin/env python3
"""Hold every release statement in the package to the version the package carries.

A reader meets the current release in many places: the install pin and the curl line in
README.md, the release tag in llms.txt, the Status line in docs/ABOUT.md, the python
package line in docs/RELEASING.md, CITATION.cff, the "at version" sentences in
CONTRIBUTING.md and GOVERNANCE.md, and the template's targeted version. Until this check
existed nothing compared them: the archived repository's README said 0.4.0 while its
code was 0.5.0.

What must agree, always:

* The authority set: pyproject.toml `version`, `meta.version` in vocabulary.yaml and its
  `# version:` header line are one value.
* Every version a statement names equals that value. A statement that vanishes is a
  failure, so deleting a pin cannot make the check pass.
* The date in the README and ABOUT Status lines equals CITATION.cff `date-released`.
* Every sha256 stated for vocabulary.yaml (README quick start, RELEASING.md) is one
  value, and it names a published registry copy at
  pages/vocab/v1/registry/sha256-<digest>.yaml whose bytes hash to that digest and whose
  `meta.version` is the version the statements name. A digest left behind by a version
  bump, or a version left behind by a digest, therefore fails.

What may lag, on purpose: the stated digest is the digest of the bytes at the release tag,
and the quick start curls that tag, so it stays correct while vocabulary.yaml gains
changes that no release carries yet (docs/RELEASING.md: a release is one commit that
states the new version everywhere). The working vocabulary.yaml is therefore not required
to hash to the stated digest; when it does not, this prints a NOTE and passes. The scripts
that pin the built wheel's bytes are the release tool's, not statements to a reader.

`--self-test` copies the package, requires the copy to pass, then reintroduces each drift
(a 0.4.0-style stale pin, a stale tag, a stale digest, a digest from another release, a
deleted statement, a tampered copy) and requires each to fail by name.

Exit 0 every statement agrees, 1 at least one does not, 2 the check could not run.
"""

from __future__ import annotations

import hashlib
import re
import shutil
import sys
import tempfile
import tomllib
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

import yaml

PACKAGE = Path(__file__).resolve().parent.parent
_VERSION = r"(\d+\.\d+\.\d+)"
_DIGEST = r"([0-9a-f]{64})"
_DATE = r"([A-Z][a-z]+ \d{1,2}, \d{4})"


@dataclass(frozen=True)
class Rule:
    """One statement: a file, the pattern that finds it, and what the capture is."""

    file: str
    kind: str  # version | digest | date
    pattern: str
    what: str


RULES = (
    Rule("README.md", "version", rf"pip install agent-evidence-vocabulary=={_VERSION}", "the install pin"),
    Rule("README.md", "version", rf"Release v{_VERSION},", "the Status release"),
    Rule("README.md", "version", rf"/agent-evidence-vocabulary-v{_VERSION}/", "the curl tag"),
    Rule("README.md", "digest", rf"{_DIGEST}\s+vocabulary\.yaml", "the quick-start sha256"),
    Rule("README.md", "date", rf"Release v{_VERSION}, tagged {_DATE}", "the Status date"),
    Rule("llms.txt", "version", rf"Release tag: `v{_VERSION}`", "the release tag"),
    Rule("docs/ABOUT.md", "version", rf"^Version {_VERSION}, tagged", "the Status version"),
    Rule("docs/ABOUT.md", "date", rf"^Version {_VERSION}, tagged {_DATE}", "the Status date"),
    Rule("docs/RELEASING.md", "version", rf"`agent-evidence-vocabulary` {_VERSION}\.", "the python package"),
    Rule("docs/RELEASING.md", "version", rf"data release `v{_VERSION}`", "the data release"),
    Rule("docs/RELEASING.md", "version", rf"agent_evidence_vocabulary-{_VERSION}-py3", "the wheel name"),
    Rule("docs/RELEASING.md", "digest", rf"SHA-256\s+`{_DIGEST}`", "the python package sha256"),
    Rule("CITATION.cff", "version", rf"^version: {_VERSION}$", "the citation version"),
    Rule("CONTRIBUTING.md", "version", rf"At version {_VERSION}", "the at-version sentence"),
    Rule("CONTRIBUTING.md", "version", rf'vocabulary_version_targeted: "{_VERSION}"', "the worked example"),
    Rule("GOVERNANCE.md", "version", rf"consequence at {_VERSION} is", "the canonical-count sentence"),
    Rule("GOVERNANCE.md", "version", rf"It is empty at {_VERSION},", "the review-by sentence"),
    Rule("crosswalk/TEMPLATE.yaml", "version", rf'vocabulary_version_targeted: "{_VERSION}"', "the template"),
)


def _published_copy(pages: Path, digest: str) -> Path:
    return pages / "vocab" / "v1" / "registry" / f"sha256-{digest}.yaml"


def _authority(root: Path) -> tuple[dict[str, str], list[str]]:
    errors: list[str] = []
    found: dict[str, str] = {}
    found["pyproject.toml version"] = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))[
        "project"]["version"]
    text = (root / "vocabulary.yaml").read_text(encoding="utf-8")
    found["vocabulary.yaml meta.version"] = str(yaml.safe_load(text)["meta"]["version"])
    header = re.search(r'^# version: "([^"]+)"$', text, re.MULTILINE)
    if header is None:
        errors.append('vocabulary.yaml: no `# version: "X"` header line')
    else:
        found["vocabulary.yaml header"] = header.group(1)
    return found, errors


def _statements(root: Path, errors: list[str]) -> list[tuple[Rule, str]]:
    found: list[tuple[Rule, str]] = []
    for rule in RULES:
        path = root / rule.file
        if not path.is_file():
            errors.append(f"{rule.file}: missing, so {rule.what} cannot be read")
            continue
        hits = re.findall(rule.pattern, path.read_text(encoding="utf-8"), re.MULTILINE)
        if not hits:
            errors.append(f"{rule.file}: {rule.what} is not stated (no match for its pattern)")
        found.extend((rule, hit if isinstance(hit, str) else hit[-1]) for hit in hits)
    return found


def check(root: Path, pages: Path) -> tuple[list[str], list[str]]:
    """Return (failures, notes) for the package at ``root`` with published pages at ``pages``."""
    authority, errors = _authority(root)
    notes: list[str] = []
    if len(set(authority.values())) != 1:
        errors.append(f"the version sources disagree: {authority}")
    version = authority["pyproject.toml version"]
    statements = _statements(root, errors)
    for rule, value in statements:
        if rule.kind == "version" and value != version:
            errors.append(f"{rule.file}: {rule.what} says {value}, the package is {version}")
    stated_date = datetime.strptime(
        str(yaml.safe_load((root / "CITATION.cff").read_text(encoding="utf-8"))["date-released"]), "%Y-%m-%d")
    for rule, value in statements:
        if rule.kind == "date" and datetime.strptime(value, "%B %d, %Y") != stated_date:
            errors.append(f"{rule.file}: {rule.what} says {value}, CITATION.cff date-released is "
                          f"{stated_date:%Y-%m-%d}")
    digests = {value for rule, value in statements if rule.kind == "digest"}
    if len(digests) > 1:
        errors.append(f"the stated sha256 values disagree: {sorted(digests)}")
    for digest in sorted(digests):
        errors.extend(_check_published(pages, digest, version))
    return errors, notes + _unreleased_note(root, digests, version)


def _check_published(pages: Path, digest: str, version: str) -> list[str]:
    copy = _published_copy(pages, digest)
    where = copy.relative_to(pages.parent) if pages.parent in copy.parents else copy
    if not copy.is_file():
        return [f"stated sha256 {digest} names no published registry copy ({where})"]
    raw = copy.read_bytes()
    if hashlib.sha256(raw).hexdigest() != digest:
        return [f"{where}: its bytes do not hash to the digest in its name"]
    published = str(yaml.safe_load(raw)["meta"]["version"])
    if published != version:
        return [f"stated sha256 {digest} is the registry of {published}, but the statements name {version}"]
    return []


def _unreleased_note(root: Path, digests: set[str], version: str) -> list[str]:
    current = hashlib.sha256((root / "vocabulary.yaml").read_bytes()).hexdigest()
    if digests and current not in digests:
        message = f"vocabulary.yaml has changes the {version} release does not carry; "
        return [message + "the stated digest names the released bytes"]
    return []


def _tree(tmp: Path) -> tuple[Path, Path]:
    """A copy of everything the check reads, in the repository's own layout."""
    root = tmp / "packages" / "vocabulary"
    pages = tmp / "pages"
    root.mkdir(parents=True)
    for name in ("README.md", "llms.txt", "CITATION.cff", "CONTRIBUTING.md", "GOVERNANCE.md", "pyproject.toml",
                 "vocabulary.yaml"):
        shutil.copy2(PACKAGE / name, root / name)
    for sub in ("docs", "crosswalk"):
        (root / sub).mkdir()
        for path in (PACKAGE / sub).glob("*.*"):
            shutil.copy2(path, root / sub / path.name)
    shutil.copytree(PACKAGE.parents[1] / "pages" / "vocab" / "v1" / "registry", pages / "vocab" / "v1" / "registry")
    return root, pages


def _edit(path: Path, old: str, new: str) -> None:
    text = path.read_text(encoding="utf-8")
    if old not in text:
        raise AssertionError(f"self-test fixture: {old!r} not in {path.name}")
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


def self_test() -> list[str]:
    """Each drift must be refused by name; a change nothing released must pass."""
    failures: list[str] = []
    with tempfile.TemporaryDirectory() as tmp_name:
        base = Path(tmp_name) / "base"
        root, pages = _tree(base)
        errors, _ = check(root, pages)
        if errors:
            return [f"self-test: the unmodified copy was refused: {errors}"]
        version = _authority(root)[0]["pyproject.toml version"]
        digest = next(v for r, v in _statements(root, []) if r.kind == "digest")
        other = next(p.stem[len("sha256-"):] for p in (pages / "vocab" / "v1" / "registry").glob("sha256-*.yaml")
                     if p.stem != f"sha256-{digest}")
        flipped = digest[:-1] + ("0" if digest[-1] != "0" else "1")
        cases = [
            ("a stale install pin", "README.md", f"agent-evidence-vocabulary=={version}",
             "agent-evidence-vocabulary==0.4.0", "the install pin says 0.4.0"),
            ("a stale curl tag", "README.md", f"agent-evidence-vocabulary-v{version}/", "agent-evidence-vocabulary-v0.4.0/",
             "the curl tag says 0.4.0"),
            ("a stale Status release", "README.md", f"Release v{version},", "Release v0.4.0,",
             "the Status release says 0.4.0"),
            ("a stale release tag in llms.txt", "llms.txt", f"`v{version}`", "`v0.4.0`", "the release tag says 0.4.0"),
            ("a stale ABOUT status", "docs/ABOUT.md", f"Version {version}, tagged", "Version 0.4.0, tagged",
             "the Status version says 0.4.0"),
            ("a stale wheel name", "docs/RELEASING.md", f"agent_evidence_vocabulary-{version}-py3",
             "agent_evidence_vocabulary-0.4.0-py3", "the wheel name says 0.4.0"),
            ("a stale citation version", "CITATION.cff", f"version: {version}", "version: 0.4.0",
             "the citation version says 0.4.0"),
            ("a stale date", "README.md", "tagged October 26, 2026", "tagged October 20, 2026", "the Status date says"),
            ("a digest nothing published", "README.md", digest, flipped, "names no published registry copy"),
            ("a digest of another release", "README.md", digest, other, "is the registry of"),
            ("two digests that disagree", "docs/RELEASING.md", digest, other, "sha256 values disagree"),
            ("a version bump with no digest", "pyproject.toml", f'version = "{version}"', 'version = "9.9.9"',
             "the version sources disagree"),
            ("a deleted pin", "README.md", f"pip install agent-evidence-vocabulary=={version}",
             "pip install agent-evidence-vocabulary", "the install pin is not stated"),
        ]
        for label, name, old, new, expect in cases:
            case_root, case_pages = _tree(Path(tmp_name) / label.replace(" ", "-"))
            _edit(case_root / name, old, new)
            got, _ = check(case_root, case_pages)
            if not any(expect in e for e in got):
                failures.append(f"self-test: {label} was not refused by name (wanted {expect!r}), got {got}")
        tamper_root, tamper_pages = _tree(Path(tmp_name) / "tampered")
        with _published_copy(tamper_pages, digest).open("ab") as handle:
            handle.write(b"# edited after publication\n")
        got, _ = check(tamper_root, tamper_pages)
        if not any("do not hash to the digest in its name" in e for e in got):
            failures.append(f"self-test: a tampered published copy was not refused: {got}")
        ahead_root, ahead_pages = _tree(Path(tmp_name) / "ahead")
        with (ahead_root / "vocabulary.yaml").open("a", encoding="utf-8") as handle:
            handle.write("# a change no release carries yet\n")
        got, notes = check(ahead_root, ahead_pages)
        if got or not notes:
            failures.append(f"self-test: a change nothing has released must pass with a note: {got} {notes}")
    return failures


def main(argv: list[str]) -> int:
    try:
        if "--self-test" in argv:
            failures = self_test()
            notes: list[str] = []
        else:
            failures, notes = check(PACKAGE, PACKAGE.parents[1] / "pages")
    except (OSError, KeyError, ValueError, yaml.YAMLError, tomllib.TOMLDecodeError, AssertionError) as exc:
        print(f"check could not run: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    for note in notes:
        print(f"NOTE {note}")
    for failure in failures:
        print(f"FAIL {failure}", file=sys.stderr)
    if failures:
        return 1
    print("check_release_statements: " + ("every drift refused" if "--self-test" in argv else "every statement agrees"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
