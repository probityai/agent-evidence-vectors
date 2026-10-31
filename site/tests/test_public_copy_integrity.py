"""A retained public copy must survive the actual Pages artifact contract."""
import hashlib
import json
from pathlib import Path

import pytest

import build

ROOT = Path(__file__).resolve().parents[1]
SOURCE = "experiments/nist-ai300-1-checker-2026-10-13/source/workflows/nist-ai-300-1.yml"


@pytest.mark.parametrize("destination", [
    "source/.github/workflows/workflow.yml",
    "source/.git/config",
    ".git",
])
def test_deployed_uploader_exclusions_refuse_before_copy(destination, monkeypatch, tmp_path):
    monkeypatch.setattr(build, "COPIES", [(SOURCE, destination, "lab")])
    with pytest.raises(ValueError, match="excluded by the Pages uploader"):
        build.copy_public_files(tmp_path, {"lab"})
    assert not list(tmp_path.iterdir())


@pytest.mark.parametrize("destination", [
    "source/workflows/workflow.yml",
    ".nojekyll",
    ".well-known/workflow.yml",
    "source/.github-backup/workflow.yml",
    ".github.yml",
    "source/.gitignore",
])
def test_other_dot_names_and_retained_workflow_bytes_remain_valid(destination, monkeypatch, tmp_path):
    monkeypatch.setattr(build, "COPIES", [(SOURCE, destination, "lab")])
    build.copy_public_files(tmp_path, {"lab"})
    assert (tmp_path / destination).read_bytes() == (ROOT / SOURCE).read_bytes()


def test_unbuilt_page_does_not_attempt_copy(monkeypatch, tmp_path):
    monkeypatch.setattr(build, "COPIES", [("missing", "source/.github/unused", "unbuilt")])
    build.copy_public_files(tmp_path, {"lab"})
    assert not list(tmp_path.iterdir())


@pytest.mark.parametrize("path, original_url, digest", [('experiments/nist-ai300-1-checker-2026-10-13/source/workflows/nist-ai-300-1.yml', 'https://raw.githubusercontent.com/probityai/agent-evidence-vectors/2212fe0fb413003b1b329e4c4b034c45746f571d/.github/workflows/nist-ai-300-1.yml', '7602f2fca48a01d4fe6e3f51777ec150520688bb1d572918de3c91935c3419d1'), ('experiments/signed-history-boundaries-2026-10-13/source/workflows/ci.yml', 'https://raw.githubusercontent.com/probityai/agent-evidence-vectors/33d545104ff2f8c124cff465c96c013eeb809156/.github/workflows/ci.yml', 'a6fe1c331ebcdaab779df225d45b0b837f3c8b545f5bb086f4551eb3bc33dcd9'), ('experiments/ratchet-benign-heredoc-2026-10-15/source/workflows/ci.yml', 'https://raw.githubusercontent.com/probityai/ratchet/b2800b26ec6cf60fee8e95682660846f674f97c2/.github/workflows/ci.yml', '577b8b33e8d84584ad3bb5e613389cfacd85c3ece45dff049878ae0d06dbf5fc')])
def test_relocated_public_workflow_preserves_its_original_source(path, original_url, digest):
    assert hashlib.sha256((ROOT / path).read_bytes()).hexdigest() == digest
    packet = path.split("/source/", 1)[0]
    source_path = "source/" + path.split("/source/", 1)[1]
    provenance = json.loads((ROOT / packet / "provenance.json").read_text())
    row = next(row for row in provenance["sources"] if row["path"] == source_path)
    assert row["url"] == original_url and "/.github/workflows/" in original_url
    assert row["sha256"] == digest
    assert (path, path, "lab") in build.COPIES
