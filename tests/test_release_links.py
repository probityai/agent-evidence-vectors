"""Tests for scripts/release_links.py: the release gate on a manifest's repository links."""

import importlib.util
import json
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1]


def _load(name: str):
    spec = importlib.util.spec_from_file_location(name, _ROOT / "scripts" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


release_links = _load("release_links")
workspace = _load("workspace")

REPOS = {
    "probityai/agent-evidence-vectors": {
        "full_name": "probityai/agent-evidence-vectors",
        "private": False,
        "archived": False,
    },
    "probityai/agent-evidence": {
        "full_name": "probityai-archive/agent-evidence",
        "private": False,
        "archived": True,
    },
    "probityai/probity-runtime": {
        "full_name": "probityai/probity-runtime",
        "private": True,
        "archived": False,
    },
    "probityai/old-name": {"full_name": "probityai/new-name", "private": False, "archived": False},
    "probityai/frozen": {"full_name": "probityai/frozen", "private": False, "archived": True},
}
PATHS = {("probityai/agent-evidence-vectors", "main", "crates/dsse")}


def repo_lookup(owner: str, repo: str):
    return REPOS.get(f"{owner}/{repo}")


def path_lookup(full_name: str, ref: str, path: str) -> bool:
    return (full_name, ref, path) in PATHS


def cargo(tmp_path: Path, repository: str, homepage: str = "") -> Path:
    body = f'[package]\nname = "x"\nversion = "0.1.0"\nrepository = "{repository}"\n'
    if homepage:
        body += f'homepage = "{homepage}"\n'
    (tmp_path / "Cargo.toml").write_text(body)
    return tmp_path / "Cargo.toml"


def check(manifest: Path) -> list[str]:
    return release_links.check_manifest(manifest, repo_lookup, path_lookup)


def test_a_live_public_repository_passes(tmp_path: Path) -> None:
    manifest = cargo(
        tmp_path,
        "https://github.com/probityai/agent-evidence-vectors",
        "https://github.com/probityai/agent-evidence-vectors/tree/main/crates/dsse#readme",
    )
    assert check(manifest) == []


def test_a_link_that_lands_on_the_archive_organisation_is_refused(tmp_path: Path) -> None:
    problems = check(cargo(tmp_path, "https://github.com/probityai/agent-evidence"))
    assert any("archived" in p for p in problems)
    assert any("redirects to probityai-archive/agent-evidence" in p for p in problems)


def test_a_private_repository_is_refused(tmp_path: Path) -> None:
    assert any(
        "private" in p
        for p in check(cargo(tmp_path, "https://github.com/probityai/probity-runtime"))
    )


def test_a_renamed_repository_is_refused_even_though_it_still_opens(tmp_path: Path) -> None:
    assert any(
        "probityai/new-name" in p
        for p in check(cargo(tmp_path, "https://github.com/probityai/old-name"))
    )


def test_an_archived_repository_in_the_organisation_is_refused(tmp_path: Path) -> None:
    assert any(
        "archived" in p for p in check(cargo(tmp_path, "https://github.com/probityai/frozen"))
    )


def test_a_repository_that_does_not_exist_is_refused(tmp_path: Path) -> None:
    assert any(
        "no repository" in p
        for p in check(cargo(tmp_path, "https://github.com/probityai/never-was"))
    )


def test_another_owner_is_refused(tmp_path: Path) -> None:
    assert any(
        "not 'probityai'" in p for p in check(cargo(tmp_path, "https://github.com/someone/else"))
    )


def test_a_path_that_does_not_exist_on_its_branch_is_refused(tmp_path: Path) -> None:
    manifest = cargo(
        tmp_path,
        "https://github.com/probityai/agent-evidence-vectors",
        "https://github.com/probityai/agent-evidence-vectors/blob/main/docs/gone.md",
    )
    assert any("docs/gone.md" in p for p in check(manifest))


def test_a_manifest_with_no_github_link_is_refused(tmp_path: Path) -> None:
    (tmp_path / "Cargo.toml").write_text('[package]\nname = "x"\nversion = "0.1.0"\n')
    assert any("no GitHub repository link" in p for p in check(tmp_path / "Cargo.toml"))


def test_pyproject_urls_are_read(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "x"\nversion = "0.1.0"\n[project.urls]\n'
        'Source = "https://github.com/probityai/agent-evidence/tree/main/packages/x"\n'
        'Downloads = "https://pepy.tech/projects/x"\n'
    )
    problems = check(tmp_path / "pyproject.toml")
    assert problems and all("urls.Source" in p for p in problems)


def test_package_json_repository_forms_are_read(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text(
        json.dumps(
            {
                "name": "x",
                "version": "0.1.0",
                "repository": {
                    "type": "git",
                    "url": "git+https://github.com/probityai/agent-evidence.git",
                },
                "bugs": {"url": "https://github.com/probityai/agent-evidence-vectors/issues"},
            }
        )
    )
    problems = check(tmp_path / "package.json")
    assert problems and all("repository" in p for p in problems)


def test_release_target_stops_on_an_unusable_link_only_when_asked(
    tmp_path: Path, monkeypatch
) -> None:
    unit = tmp_path / "crates" / "x"
    unit.mkdir(parents=True)
    cargo(unit, "https://github.com/probityai/agent-evidence")
    (tmp_path / "release.toml").write_text(
        '[[unit]]\nprefix = "x"\nname = "x"\nregistry = "crates.io"\ndirectory = "crates/x"\n'
    )
    assert workspace.release_target("x-v0.1.0", tmp_path)["version"] == "0.1.0"
    monkeypatch.setattr(release_links, "github_repo", repo_lookup)
    monkeypatch.setattr(workspace, "_release_links", lambda: release_links)
    monkeypatch.setattr(
        release_links,
        "check_manifest",
        lambda m, r=repo_lookup, p=path_lookup: (
            release_links.check_manifest.__wrapped__(m, r, p)
            if hasattr(release_links.check_manifest, "__wrapped__")
            else [f"{m}: refused"]
        ),
    )
    with pytest.raises(SystemExit, match="nowhere useful"):
        workspace.release_target("x-v0.1.0", tmp_path, check_links=True)


def test_release_resolve_step_reads_github_with_the_run_token():
    """The link check runs in release.yml's resolve job. Without a token it reads
    GitHub anonymously (60 requests an hour per runner IP), so a release can fail
    on a shared runner's spent quota rather than on a bad link."""
    yaml = pytest.importorskip("yaml")
    workflow = yaml.safe_load((_ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8"))
    steps = workflow["jobs"]["resolve"]["steps"]
    target = next(step for step in steps if step.get("id") == "target")
    assert "workspace.py release-target" in target["run"]
    assert target.get("env", {}).get("GH_TOKEN") == "${{ github.token }}"
