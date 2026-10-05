#!/usr/bin/env python3
"""Mutation tests for ``distribution-gate.py``.

The control uses a committed, tagged copy of the gate's real inputs. Each
mutation must change that copy, exit nonzero, and identify the broken claim.
The cases cover recipe location and bytes, release pins, module paths, and
both directions of corpus-table and run-form membership.

Usage: ``python3 scripts/distribution-gate-test.py``.
"""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Callable
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
GATE_REL = Path("scripts") / "distribution-gate.py"
RECIPE_REL = Path("docs/reference/release-verification.md")
PAGE_REL = Path("DISTRIBUTION.md")
CITATION_REL = Path("CITATION.cff")
GOMOD_REL = Path("go.mod")
FORM_REL = Path(".github") / "ISSUE_TEMPLATE" / "independent-run.yml"
INSTALL_LINE = re.compile(r"^go install (\S+)@(v\S+)\s*$", re.MULTILINE)
OTHER_OWNER = "github.com/not-this-owner/agent-evidence-vectors"


def _digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _git(root: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-C", str(root), *args],
        check=True,
        capture_output=True,
        text=True,
    )


def _module_of(root: Path) -> str:
    found = re.findall(r"^module\s+(\S+)\s*$", (root / GOMOD_REL).read_text(), re.MULTILINE)
    assert len(found) == 1, f"the staged go.mod carries {len(found)} module lines"
    return str(found[0])


def _install_of(root: Path) -> tuple[str, str]:
    found = INSTALL_LINE.search((root / PAGE_REL).read_text(encoding="utf-8"))
    assert found is not None, "the staged page carries no `go install ...@vX` line"
    return found.group(1), found.group(2)


def _repair_install_path(root: Path) -> None:
    """Point the staged page's install command at the staged module path.

    Asserted as a POST-condition rather than as a diff, so this keeps holding
    once the tree itself names the current path and the repair becomes a no-op.
    """
    module = _module_of(root)
    package, tag = _install_of(root)
    suffix = package.rsplit("/cmd/", 1)[-1] if "/cmd/" in package else ""
    wanted = f"{module}/cmd/{suffix}" if suffix else module
    page = root / PAGE_REL
    page.write_text(
        page.read_text(encoding="utf-8").replace(
            f"go install {package}@{tag}", f"go install {wanted}@{tag}", 1
        ),
        encoding="utf-8",
    )
    fixed, _ = _install_of(root)
    if fixed != module and not fixed.startswith(f"{module}/"):
        raise AssertionError(
            f"the staged page still installs from {fixed!r}, which is not under {module!r}"
        )


def _staged_copy(tmp: Path) -> Path:
    """A committed, tagged git repository holding everything the gate reads."""
    root = tmp / "tree"
    (root / "scripts").mkdir(parents=True)
    (root / FORM_REL.parent).mkdir(parents=True)
    shutil.copy2(REPO_ROOT / GATE_REL, root / GATE_REL)
    for rel in (RECIPE_REL, PAGE_REL, CITATION_REL, FORM_REL, GOMOD_REL,
                Path("README.md"), Path("docs/guides/runner.md")):
        (root / rel.parent).mkdir(parents=True, exist_ok=True)
        shutil.copy2(REPO_ROOT / rel, root / rel)
    for manifest in sorted(REPO_ROOT.glob("vectors*/MANIFEST.json")):
        target = root / manifest.parent.name / "MANIFEST.json"
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(manifest, target)
    _repair_install_path(root)
    _git(root, "init", "--quiet")
    _git(root, "config", "user.email", "gate@example.invalid")
    _git(root, "config", "user.name", "gate")
    # Pinned locally rather than inherited. A developer with `tag.gpgsign true`
    # in their global config turns the lightweight tag below into a signed
    # annotated one, which git then refuses for want of a message -- so the
    # fixture would fail on their machine and pass in CI, for a reason that has
    # nothing to do with what is under test.
    _git(root, "config", "tag.gpgSign", "false")
    _git(root, "config", "commit.gpgSign", "false")
    _git(root, "add", "-A")
    _git(root, "commit", "--quiet", "-m", "staged")
    # The tag the page pins has to exist and has to carry this go.mod, because
    # that pair is exactly what the gate reads: the module path a consumer is
    # told to fetch, at the version they are told to pin it to.
    _git(root, "tag", _install_of(root)[1])
    selected = subprocess.check_output(
        ["git", "-C", str(root), "rev-parse", "HEAD"], text=True,
    ).strip()
    for rel in (PAGE_REL, Path("README.md"), Path("docs/guides/runner.md")):
        path = root / rel
        path.write_text(re.sub(
            r"(uvx --from git\+https://github.com/probityai/agent-evidence-vectors@)\S+",
            rf"\g<1>{selected}", path.read_text(encoding="utf-8")), encoding="utf-8")
    return root


def _run_gate(root: Path) -> tuple[int, str]:
    proc = subprocess.run(
        [sys.executable, str(root / GATE_REL), "--root", str(root)],
        capture_output=True,
        text=True,
        cwd=str(root),
    )
    return proc.returncode, proc.stdout + proc.stderr


def _edit(root: Path, rel: Path, change: Callable[[str], str]) -> None:
    path = root / rel
    before = path.read_text(encoding="utf-8")
    after = change(before)
    if _digest(before) == _digest(after):
        raise AssertionError(f"the mutation of {rel} changed nothing, so the case tests nothing")
    path.write_text(after, encoding="utf-8")


def case_recipe_drift(root: Path) -> str:
    """One command changed in the reference page and not in the copy."""
    _edit(
        root,
        PAGE_REL,
        lambda text: text.replace(
            "python3 scripts/release-digests.py --check",
            "python3 scripts/release-digests.py --verify",
            1,
        ),
    )
    return "the verification recipe differs"


def released_version(root: Path) -> str:
    """The version CITATION.cff declares, read rather than hardcoded.

    Two cases below used to name the version of the day as a literal, and a
    release turned both of them into no-ops: the mutation replaced a string the
    page no longer contained, the page came back unchanged, and a case that
    changes nothing asserts nothing. It was caught by the harness refusing a
    mutation that edited no bytes, which is the only reason it was not a pair of
    green cases testing nothing for a whole release cycle.
    """
    text = (root / CITATION_REL).read_text(encoding="utf-8")
    found = re.findall(r"^version:\s*(\S+)\s*$", text, re.MULTILINE)
    if len(found) != 1:
        raise SystemExit(
            f"test setup: {CITATION_REL} carries {len(found)} version lines; "
            "the cases below mutate relative to exactly one."
        )
    return str(found[0]).strip("'\"")


def case_tag_behind(root: Path) -> str:
    """The citation file moves to the next release and the prose does not."""
    current = released_version(root)
    _edit(
        root,
        CITATION_REL,
        lambda text: text.replace(f"version: {current}", "version: 99.0.0", 1),
    )
    return "the released version is"


def case_untabled_corpus(root: Path) -> str:
    """A corpus lands and the inbound page never mentions it."""
    directory = root / "vectors-untabled"
    directory.mkdir()
    (directory / "MANIFEST.json").write_text(
        json.dumps({"suite": "untabled-conformance", "counts": {"accept": 1, "reject": 1}}),
        encoding="utf-8",
    )
    _git(root, "add", "-A")
    _git(root, "commit", "--quiet", "-m", "a corpus with no row")
    return "does not table it"


def case_unoffered_corpus(root: Path) -> str:
    """A corpus a reporter cannot name on the form we point them at."""
    _edit(
        root,
        FORM_REL,
        lambda text: text.replace('        - "vectors-aci/"\n', "", 1),
    )
    return "does not offer it"


def case_phantom_option(root: Path) -> str:
    """An option outliving the corpus it offers."""
    _edit(
        root,
        FORM_REL,
        lambda text: text.replace(
            '        - "vectors-aci/"\n',
            '        - "vectors-aci/"\n        - "vectors-withdrawn/"\n',
            1,
        ),
    )
    return "offers `vectors-withdrawn/`"


def case_stale_tag_in_prose(root: Path) -> str:
    """A stale tag outside the named claim sites must still fail."""
    _edit(
        root,
        PAGE_REL,
        lambda text: text + "\nThe released tag is `v0.9.0`.\n",
    )
    return "the backticked version token `v0.9.0`"


def case_phantom_row(root: Path) -> str:
    """A row outlives the corpus it advertises."""
    _edit(
        root,
        PAGE_REL,
        lambda text: text.replace(
            "| `vectors-aci/` |",
            "| `vectors-withdrawn/` | `withdrawn-conformance` | nothing that ships |\n"
            "| `vectors-aci/` |",
            1,
        ),
    )
    return "no such corpus is tracked"


def case_suite_renamed(root: Path) -> str:
    """A corpus renames its suite and the table keeps the old name."""
    manifest = root / "vectors-aci" / "MANIFEST.json"
    loaded = json.loads(manifest.read_text(encoding="utf-8"))
    loaded["suite"] = "aci-renamed"
    _edit(
        root,
        Path("vectors-aci") / "MANIFEST.json",
        lambda _: json.dumps(loaded, indent=2),
    )
    return "tables it as"


def case_install_path_not_ours(root: Path) -> str:
    """The page installs from a module path this repository does not publish."""
    package, tag = _install_of(root)
    _edit(
        root,
        PAGE_REL,
        lambda text: text.replace(
            f"go install {package}@{tag}",
            f"go install {OTHER_OWNER}/cmd/aee-verify@{tag}",
            1,
        ),
    )
    return "does not publish"


def case_tag_predates_the_module_path(root: Path) -> str:
    """The pinned tag was cut before the module path moved.

    Built the way it really arrives: the tag stays where it is, on a commit
    whose `go.mod` declares the old path, while the working tree moves on. Every
    proxy endpoint but `.mod` answers 200 for both spellings in that state,
    which is why it shipped.
    """
    module = _module_of(root)
    _, tag = _install_of(root)
    gomod = root / GOMOD_REL
    current = gomod.read_text(encoding="utf-8")
    gomod.write_text(current.replace(module, OTHER_OWNER, 1), encoding="utf-8")
    _git(root, "commit", "--quiet", "-a", "-m", "the module path before it moved")
    _git(root, "tag", "-f", tag)
    gomod.write_text(current, encoding="utf-8")
    _git(root, "commit", "--quiet", "-a", "-m", "move the module path")
    return "declares the module as"


def case_pinned_tag_absent(root: Path) -> str:
    """A tag the clone does not hold must read as a check that did not run."""
    _git(root, "tag", "-d", _install_of(root)[1])
    return "was NOT checked"


def case_two_module_lines(root: Path) -> str:
    """Two spellings of what this repository publishes is not a longer answer."""
    _edit(
        root,
        GOMOD_REL,
        lambda text: text + f"\nmodule {OTHER_OWNER}\n",
    )
    return "top-level `module` lines"


def case_heading_renamed(root: Path) -> str:
    """The recipe stops being findable by its own name."""
    _edit(
        root,
        RECIPE_REL,
        lambda text: text.replace(
            "## Verify a release without trusting us",
            "## Checking a release",
            1,
        ),
    )
    return "has no heading"


def case_recipe_missing(root: Path) -> str:
    """A heading without a recipe cannot pass by finding another section."""
    _edit(
        root,
        RECIPE_REL,
        lambda text: re.sub(r"(?ms)^```[^\n]*\n.*?^```[ \t]*$", "", text, count=1),
    )
    return "no fenced block under it"


def case_recipe_moved(root: Path) -> str:
    """The recipe is present but belongs to a different section."""
    _edit(
        root,
        RECIPE_REL,
        lambda text: text.replace("```bash", "## A different section\n\n```bash", 1),
    )
    return "no fenced block under it"


def case_recipe_unclosed(root: Path) -> str:
    """An opening fence without its closing line is incomplete."""
    _edit(
        root,
        RECIPE_REL,
        lambda text: re.sub(r"(?m)^```[ \t]*$", "", text, count=1),
    )
    return "is never closed"


def case_heading_duplicated(root: Path) -> str:
    """Two recipe sections would leave the checked copy ambiguous."""
    _edit(
        root,
        RECIPE_REL,
        lambda text: text + "\n## Verify a release without trusting us\n",
    )
    return "expected one"


def case_recipe_file_missing(root: Path) -> str:
    """A deleted reference page must be reported rather than skipped."""
    path = root / RECIPE_REL
    if not path.is_file():
        raise AssertionError("the staged reference page does not exist")
    path.unlink()
    return f"{RECIPE_REL} does not exist"


def case_recipe_pin_stale(root: Path) -> str:
    """Matching copies of an old recipe still name the wrong release."""
    _, tag = _install_of(root)
    for rel in (RECIPE_REL, PAGE_REL):
        _edit(
            root,
            rel,
            lambda text: text.replace(f"git checkout {tag}", "git checkout v99.0.0"),
        )
    return "the recipe's `git checkout` names v99.0.0"


def stale_consumer_pin(rel: str, route: str) -> Callable[[Path], str]:
    """Mutate an actual install command while other entry points stay correct."""
    def mutate(root: Path) -> str:
        patterns = {
            "Go install": r"(go install \S+@)v[^\s]+",
            "Python install": r"(uvx --from \S+ agent-evidence-vectors)",
            "GitHub Action": r"(- uses: probityai/agent-evidence-vectors@)v[^\s]+",
        }
        if route == "Python install":
            _edit(root, Path(rel), lambda text: re.sub(patterns[route],
                  "uvx agent-evidence-vectors==99.0.0", text, count=1))
            return f"{rel}: {route} pin"
        prefix = "v"
        _edit(root, Path(rel), lambda text: re.sub(patterns[route],
              rf"\g<1>{prefix}99.0.0", text, count=1))
        return f"{rel}: {route} pin"
    return mutate


def missing_python_command(root: Path) -> str:
    _edit(root, Path("README.md"), lambda text: re.sub(
        r"^uvx --from [^\n]+\n", "", text, count=1, flags=re.MULTILINE))
    return "README.md has no pinned Python install command"


def missing_runner_page(root: Path) -> str:
    (root / "docs/guides/runner.md").unlink()
    return "docs/guides/runner.md does not exist"


def wrong_source_pin(pin: str) -> Callable[[Path], str]:
    """A present source command can still fetch the wrong owner, ref or bytes."""
    def mutate(root: Path) -> str:
        _edit(root, Path("README.md"), lambda text: re.sub(
            r"(uvx --from )\S+( agent-evidence-vectors)",
            rf"\g<1>{pin}\g<2>", text, count=1))
        return "README.md: Python install pin"
    return mutate


def conflicting_source_pins(root: Path) -> str:
    _edit(root, Path("README.md"), lambda text: text +
          "\nuvx --from git+https://github.com/probityai/agent-evidence-vectors@main "
          "agent-evidence-vectors --self-test\n")
    return "README.md: Python install pin"


def wrong_source_entry_point(root: Path) -> str:
    version = _install_of(root)[1][1:]
    _edit(root, Path("README.md"), lambda text: re.sub(
        r"(uvx --from \S+ )agent-evidence-vectors", r"\g<1>wrong-entry-point",
        text, count=1) + f"\nuvx agent-evidence-vectors=={version} --self-test\n")
    return "README.md: unrecognized Python install command"


CASES: tuple[tuple[str, Callable[[Path], str]], ...] = (
    ("a source command fetching another owner", wrong_source_pin(
        "git+https://github.com/other-owner/agent-evidence-vectors@" + "0" * 40)),
    ("a source command following a branch", wrong_source_pin(
        "git+https://github.com/probityai/agent-evidence-vectors@main")),
    ("a source command naming different immutable bytes", wrong_source_pin(
        "git+https://github.com/probityai/agent-evidence-vectors@" + "0" * 40)),
    ("a valid source pin beside a conflicting pin", conflicting_source_pins),
    ("a wrong source executable beside a valid registry pin", wrong_source_entry_point),
    *((f"{rel} retains a stale {route} pin", stale_consumer_pin(rel, route))
      for rel in ("README.md", "DISTRIBUTION.md", "docs/guides/runner.md")
      for route in ("Go install", "Python install")),
    ("runner retains a stale Action pin",
     stale_consumer_pin("docs/guides/runner.md", "GitHub Action")),
    ("README Python command disappears", missing_python_command),
    ("runner guide disappears", missing_runner_page),
    ("a command fixed in one copy of the recipe and not the other", case_recipe_drift),
    ("the citation file released ahead of the prose", case_tag_behind),
    ("a version token in prose left behind by a release", case_stale_tag_in_prose),
    ("a tracked corpus with no row on the inbound page", case_untabled_corpus),
    ("a tracked corpus the run form does not offer", case_unoffered_corpus),
    ("a run-form option for a corpus that is not tracked", case_phantom_option),
    ("a row for a corpus that is not tracked", case_phantom_row),
    (
        "a corpus whose suite name the table still spells the old way",
        case_suite_renamed,
    ),
    (
        "an install command for a module path this repository does not publish",
        case_install_path_not_ours,
    ),
    (
        "a pinned tag cut before the module path moved",
        case_tag_predates_the_module_path,
    ),
    ("a pinned tag this clone does not hold", case_pinned_tag_absent),
    ("a go.mod declaring the module path twice", case_two_module_lines),
    ("the recipe's heading renamed out from under the gate", case_heading_renamed),
    ("the reference recipe removed", case_recipe_missing),
    ("the recipe moved into another section", case_recipe_moved),
    ("the reference recipe's closing fence removed", case_recipe_unclosed),
    ("the recipe heading duplicated", case_heading_duplicated),
    ("the recipe reference page deleted", case_recipe_file_missing),
    ("both recipe copies retain a stale release pin", case_recipe_pin_stale),
)


def registry_control_failures() -> list[str]:
    """A current registry pin remains valid metadata without asserting availability."""
    with tempfile.TemporaryDirectory() as raw:
        registry = _staged_copy(Path(raw))
        version = _install_of(registry)[1][1:]
        for rel in (PAGE_REL, Path("README.md"), Path("docs/guides/runner.md")):
            path = registry / rel
            path.write_text(re.sub(
                r"uvx --from \S+ agent-evidence-vectors",
                "uvx agent-evidence-vectors==" + version,
                path.read_text(encoding="utf-8")), encoding="utf-8")
        code, output = _run_gate(registry)
        if code != 0:
            return [f"the current registry-pin control failed:\n{output}"]
    return []


def main() -> int:
    failures = registry_control_failures()

    with tempfile.TemporaryDirectory() as raw:
        control = _staged_copy(Path(raw))
        code, output = _run_gate(control)
        if code != 0:
            failures.append(
                "the control failed: the unmutated tree does not pass, so every refusal below "
                f"would be meaningless.\n{output}"
            )

    for label, mutate in CASES:
        with tempfile.TemporaryDirectory() as raw:
            root = _staged_copy(Path(raw))
            try:
                expected = mutate(root)
            except AssertionError as exc:
                failures.append(f"{label}: {exc}")
                continue
            code, output = _run_gate(root)
            if code == 0:
                failures.append(f"{label}: the gate passed a tree it must refuse.\n{output}")
            elif expected not in output:
                failures.append(
                    f"{label}: the gate refused but said nothing about it. Expected the refusal "
                    f"to contain {expected!r}.\n{output}"
                )

    if failures:
        print("distribution-gate-test: FAILED")
        for line in failures:
            print(f"  - {line}")
        return 1
    print(f"OK: the control passes and all {len(CASES)} mutations are refused by name.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
