"""Tests for scripts/family_pin_guard.py: an excluding sibling pin refuses a release, a widened one passes."""

import importlib.util
import json
import sys
import tomllib
from pathlib import Path

import pytest
from packaging.version import Version

ROOT = Path(__file__).resolve().parents[1]
_SPEC = importlib.util.spec_from_file_location("family_pin_guard", ROOT / "scripts" / "family_pin_guard.py")
guard = importlib.util.module_from_spec(_SPEC)
sys.modules["family_pin_guard"] = guard
_SPEC.loader.exec_module(guard)

NAMES = ["agent-evidence-vocabulary", "agent-evidence-admission", "agent-evidence-mcp", "probity-verify"]


def publish(directory: Path, name: str, version: str, requires: list[str] | None = None) -> None:
    """Write one fixture release in the shape of PyPI's JSON API."""
    document = {"info": {"name": name, "version": version, "requires_dist": requires}}
    (directory / f"{name}.json").write_text(json.dumps(document))


@pytest.fixture
def index(tmp_path: Path) -> Path:
    """The state of the index on 2026-10-26, before vocabulary 0.8.0 is released."""
    publish(tmp_path, "agent-evidence-vocabulary", "0.7.0")
    publish(tmp_path, "agent-evidence-admission", "0.2.0")
    publish(tmp_path, "probity-verify", "0.2.1", ["cryptography>=50", "agent-evidence-vocabulary~=0.7.0"])
    publish(tmp_path, "agent-evidence-mcp", "0.2.2", [
        "mcp==2.3.0", "probity-verify~=0.2.1", "agent-evidence-vocabulary~=0.7.0", "agent-evidence-admission~=0.2.0"])
    return tmp_path


@pytest.fixture
def family_file(tmp_path: Path) -> Path:
    path = tmp_path / "family.toml"
    path.write_text("packages = [" + ", ".join(f'"{n}"' for n in NAMES) + "]\n")
    return path


def run(index: Path, family_file: Path, name: str, version: str, *extra: str) -> int:
    return guard.main(["check", "--name", name, "--version", version,
                       "--metadata-dir", str(index), "--family", str(family_file), *extra])


def test_an_excluding_pin_refuses_the_release_and_names_the_sibling(index, family_file, capsys):
    assert run(index, family_file, "agent-evidence-vocabulary", "0.8.0") == 1
    err = capsys.readouterr().err
    assert "REFUSE agent-evidence-vocabulary 0.8.0" in err
    assert "probity-verify 0.2.1 requires agent-evidence-vocabulary~=0.7.0" in err
    assert "agent-evidence-mcp 0.2.2 requires agent-evidence-vocabulary~=0.7.0" in err
    assert "widened pin first" in err


def test_widening_the_pins_turns_the_same_release_green(index, family_file, capsys):
    """Mutation check: the only change between red and green is the siblings' published pin."""
    assert run(index, family_file, "agent-evidence-vocabulary", "0.8.0") == 1
    publish(index, "probity-verify", "0.2.2", ["cryptography>=50", "agent-evidence-vocabulary~=0.8.0"])
    assert run(index, family_file, "agent-evidence-vocabulary", "0.8.0") == 1
    publish(index, "agent-evidence-mcp", "0.2.3", ["agent-evidence-vocabulary>=0.7,<0.9"])
    capsys.readouterr()
    assert run(index, family_file, "agent-evidence-vocabulary", "0.8.0") == 0
    assert "PASS agent-evidence-vocabulary 0.8.0" in capsys.readouterr().out


def test_the_admission_upper_bound_pin_of_the_first_incident_is_caught(index, family_file, capsys):
    publish(index, "agent-evidence-mcp", "0.2.1", ["agent-evidence-admission<0.2"])
    assert run(index, family_file, "agent-evidence-admission", "0.2.1") == 1
    assert "agent-evidence-mcp 0.2.1 requires agent-evidence-admission<0.2" in capsys.readouterr().err


def test_a_release_inside_every_pin_passes(index, family_file):
    assert run(index, family_file, "agent-evidence-vocabulary", "0.7.1") == 0


def test_a_sibling_with_no_requirement_on_the_candidate_is_ignored(index, family_file):
    assert run(index, family_file, "probity-verify", "0.3.0") == 1  # mcp pins ~=0.2.1
    publish(index, "agent-evidence-mcp", "0.2.3", ["mcp==2.3.0"])
    assert run(index, family_file, "probity-verify", "0.3.0") == 0


def test_a_pin_behind_an_extra_still_refuses(index, family_file):
    publish(index, "probity-verify", "0.2.2", ['agent-evidence-vocabulary~=0.7.0; extra == "a2a"'])
    publish(index, "agent-evidence-mcp", "0.2.3", [])
    assert run(index, family_file, "agent-evidence-vocabulary", "0.8.0") == 1


def test_a_pin_whose_environment_marker_is_false_is_ignored(index, family_file):
    publish(index, "probity-verify", "0.2.2", ['agent-evidence-vocabulary~=0.7.0; python_version < "3"'])
    publish(index, "agent-evidence-mcp", "0.2.3", [])
    assert run(index, family_file, "agent-evidence-vocabulary", "0.8.0") == 0


def test_a_release_not_newer_than_the_published_one_cannot_break_installs(index, family_file, capsys):
    """The vocabulary data re-publish case: an older version published again."""
    assert run(index, family_file, "agent-evidence-vocabulary", "0.5.0") == 0
    assert "not newer than the published 0.7.0" in capsys.readouterr().out


def test_a_first_release_of_a_distribution_is_checked_against_the_siblings(index, family_file):
    (index / "agent-evidence-vocabulary.json").unlink()
    assert run(index, family_file, "agent-evidence-vocabulary", "0.8.0") == 1


def test_a_distribution_outside_the_family_cannot_run_the_check(index, family_file, capsys):
    assert run(index, family_file, "somebody-else", "1.0.0") == 2
    assert "CHECK DID NOT RUN" in capsys.readouterr().err


def test_an_unreadable_sibling_fails_closed(index, family_file, capsys):
    (index / "probity-verify.json").write_text("{not json")
    assert run(index, family_file, "agent-evidence-vocabulary", "0.7.1") == 2
    assert "CHECK DID NOT RUN" in capsys.readouterr().err


def test_a_missing_sibling_fails_closed(index, family_file):
    (index / "agent-evidence-mcp.json").unlink()
    assert run(index, family_file, "agent-evidence-vocabulary", "0.7.1") == 2


def test_pins_out_lists_every_sibling_at_its_newest_version_and_not_the_candidate(index, family_file, tmp_path):
    out = tmp_path / "pins.txt"
    assert run(index, family_file, "agent-evidence-vocabulary", "0.7.1", "--pins-out", str(out)) == 0
    assert out.read_text().splitlines() == [
        "agent-evidence-admission==0.2.0", "agent-evidence-mcp==0.2.2", "probity-verify==0.2.1"]


def test_names_are_compared_in_canonical_form(index, family_file):
    publish(index, "probity-verify", "0.2.2", ["Agent_Evidence.Vocabulary~=0.7.0"])
    publish(index, "agent-evidence-mcp", "0.2.3", [])
    assert run(index, family_file, "agent_evidence_vocabulary", "0.8.0") == 1


def test_violations_compares_prereleases_by_the_specifier_alone():
    sibling = guard.Release("probity-verify", Version("1.0"), ("agent-evidence-vocabulary>=0.8.0rc1",))
    assert guard.violations("agent-evidence-vocabulary", Version("0.8.0rc2"), [sibling]) == []


def test_every_pypi_unit_of_release_toml_is_in_the_family_list():
    units = tomllib.loads((ROOT / "release.toml").read_text())["unit"]
    pypi = {guard.canonicalize_name(u["name"]) for u in units if u["registry"] == "pypi"}
    assert pypi <= set(guard.family())


def test_the_family_list_names_are_canonical_and_unique():
    raw = tomllib.loads(guard.FAMILY_FILE.read_text())["packages"]
    assert raw == [guard.canonicalize_name(n) for n in raw]
    assert len(raw) == len(set(raw))


def test_every_pypi_publish_job_waits_for_a_guard_job():
    lines = (ROOT / ".github" / "workflows" / "release.yml").read_text().splitlines()
    publishers = {}
    current = None
    for line in lines:
        if line.startswith("  ") and not line.startswith("   ") and line.rstrip().endswith(":"):
            current = line.strip().rstrip(":")
        elif current and line.startswith("    needs:"):
            publishers[current] = line
    pypi = ["publish", "publish-agent-evidence-vocabulary",
            "publish-agent-evidence-admission", "publish-jcs-admit-python"]
    for job in pypi:
        assert "family-pin-guard" in publishers[job], job
