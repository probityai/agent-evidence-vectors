"""Tests for scripts/workspace.py: area discovery, change mapping and release tags."""

import importlib.util
import tomllib
from pathlib import Path

import pytest

_SPEC = importlib.util.spec_from_file_location(
    "workspace", Path(__file__).resolve().parents[1] / "scripts" / "workspace.py")
workspace = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(workspace)


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    (tmp_path / "crates" / "dsse").mkdir(parents=True)
    (tmp_path / "crates" / "dsse" / "Cargo.toml").write_text('[package]\nname = "dsse"\nversion = "0.1.4"\n')
    (tmp_path / "crates" / "README.md").write_text("crates\n")
    (tmp_path / "packages" / "vocab").mkdir(parents=True)
    (tmp_path / "packages" / "vocab" / "pyproject.toml").write_text(
        '[project]\nname = "agent-evidence-vocabulary"\nversion = "0.6.0"\n')
    (tmp_path / "crates" / "dsse" / "npm").mkdir()
    (tmp_path / "crates" / "dsse" / "npm" / "package.json").write_text('{"name": "dsse", "version": "0.1.0"}\n')
    (tmp_path / "vectors").mkdir()
    (tmp_path / "actions").mkdir()
    (tmp_path / "actions" / "VERSION").write_text("0.1.0\n")
    (tmp_path / "release.toml").write_text(
        '[[unit]]\nprefix = "dsse"\nname = "dsse"\nregistry = "crates.io"\ndirectory = "crates/dsse"\n\n'
        '[[unit]]\nprefix = "agent-evidence-vocabulary"\nname = "agent-evidence-vocabulary"\n'
        'registry = "pypi"\ndirectory = "packages/vocab"\n\n'
        '[[unit]]\nprefix = "jcs-admit"\nname = "jcs-admit"\nregistry = "crates.io"\n'
        'directory = "crates/jcs-admit"\n\n'
        '[[unit]]\nprefix = "dsse-npm"\nname = "dsse"\nregistry = "npm"\ndirectory = "crates/dsse/npm"\n\n'
        '[[unit]]\nprefix = "action"\nname = "agent-evidence"\nregistry = "github-actions"\ndirectory = "actions"\n')
    return tmp_path


def test_areas_are_the_directories_with_their_own_checks(repo: Path) -> None:
    assert workspace.areas(repo) == ["actions", "crates/dsse", "packages/vocab", "vectors"]


def test_a_change_inside_an_area_selects_only_that_area(repo: Path) -> None:
    got = workspace.changed(["crates/dsse/src/lib.rs"], repo)
    assert got == {"actions": False, "crates/dsse": True, "packages/vocab": False, "vectors": False}


def test_documentation_outside_areas_selects_nothing(repo: Path) -> None:
    got = workspace.changed(["README.md", "docs/LAYOUT.md", "crates/README.md"], repo)
    assert not any(got.values())


def test_a_shared_file_selects_every_area(repo: Path) -> None:
    got = workspace.changed([".github/workflows/ci.yml"], repo)
    assert all(got.values())


def test_a_crate_tag_resolves_to_its_unit(repo: Path) -> None:
    got = workspace.release_target("dsse-v0.1.4", repo)
    assert got["directory"] == "crates/dsse" and got["registry"] == "crates.io"


def test_a_python_tag_resolves_to_its_unit(repo: Path) -> None:
    got = workspace.release_target("agent-evidence-vocabulary-v0.6.0", repo)
    assert got["name"] == "agent-evidence-vocabulary" and got["version"] == "0.6.0"


def test_an_npm_tag_resolves_to_its_unit_and_not_the_crate(repo: Path) -> None:
    got = workspace.release_target("dsse-npm-v0.1.0", repo)
    assert got["prefix"] == "dsse-npm" and got["registry"] == "npm" and got["version"] == "0.1.0"


def test_an_action_tag_resolves_to_its_version_file(repo: Path) -> None:
    got = workspace.release_target("action-v0.1.0", repo)
    assert got["registry"] == "github-actions" and got["directory"] == "actions" and got["version"] == "0.1.0"


def test_the_action_tag_resolves_in_this_repository() -> None:
    version = (workspace.ROOT / "actions" / "VERSION").read_text().strip()
    got = workspace.release_target(f"action-v{version}")
    assert got["name"] == "agent-evidence" and (workspace.ROOT / "action.yml").is_file()


@pytest.mark.parametrize("tag, message", [
    ("action-v0.1.1", "does not match"),
    ("dsse-v0.1.5", "does not match"),
    ("dsse-0.1.4", "is not <prefix>-v"),
    ("dsse-npm-v0.1.4", "does not match"),
    ("nothing-v1.0.0", "names no single unit"),
    ("jcs-admit-v0.1.2", "does not exist"),
])
def test_a_bad_tag_is_refused(repo: Path, tag: str, message: str) -> None:
    with pytest.raises(SystemExit, match=message):
        workspace.release_target(tag, repo)


def test_the_vocabulary_python_tag_resolves_in_this_repository() -> None:
    # Read the version the manifest carries now: a pinned release here broke
    # this test on every vocabulary release, because a tag naming any other
    # version is refused by design.
    manifest = Path(__file__).resolve().parents[1] / "packages" / "vocabulary" / "pyproject.toml"
    version = tomllib.loads(manifest.read_text(encoding="utf-8"))["project"]["version"]
    got = workspace.release_target(f"agent-evidence-vocabulary-python-v{version}")
    assert got["name"] == "agent-evidence-vocabulary" and got["registry"] == "pypi"
    assert got["prefix"] == "agent-evidence-vocabulary-python"


def test_the_repository_itself_reads_cleanly() -> None:
    assert isinstance(workspace.areas(), list)
    with pytest.raises(SystemExit, match="names no single unit|does not match"):
        workspace.release_target("dsse-v0.0.0")


@pytest.mark.parametrize("tag, version", [("v0.30.0", "0.30.0"), ("v1.2.3", "1.2.3"), ("v0.0.0", "0.0.0")])
def test_a_bare_corpus_tag_resolves_to_no_registry(tag: str, version: str) -> None:
    got = workspace.release_target(tag)
    assert got["registry"] == "none" and got["prefix"] == "" and got["version"] == version


@pytest.mark.parametrize("tag", ["v0.30", "v0.30.0-rc1", "V0.30.0", "v0.30.0.1", "vv0.30.0", "cited/1bc6a5a"])
def test_a_near_miss_of_a_bare_tag_is_still_refused(tag: str) -> None:
    with pytest.raises(SystemExit, match="is not <prefix>-v"):
        workspace.release_target(tag)


def test_every_prefixed_unit_tag_resolves_to_a_real_registry_in_this_repository() -> None:
    units = tomllib.loads((workspace.ROOT / "release.toml").read_text())["unit"]
    assert units
    for unit in units:
        version = workspace._version(unit, workspace.ROOT)
        got = workspace.release_target(f"{unit['prefix']}-v{version}")
        assert got["registry"] == unit["registry"] != "none", unit["prefix"]
