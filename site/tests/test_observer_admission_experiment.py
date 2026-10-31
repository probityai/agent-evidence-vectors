"""Attack checks for source pins, retained bytes, and refusal accounting."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import logging
from pathlib import Path

import pytest
from hypothesis import given, strategies as st

RUNNER = Path(__file__).resolve().parents[1] / "experiments" / "observer-admission" / "run.py"
SPEC = importlib.util.spec_from_file_location("atlas_admission_experiment", RUNNER)
assert SPEC is not None and SPEC.loader is not None
EXPERIMENT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(EXPERIMENT)


@pytest.fixture
def sources(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, Path]:
    """Provide real Git blob pins for a minimal importable-source layout."""
    root, destination = tmp_path / "observer", tmp_path / "captured"
    pins: dict[str, str] = {}
    for name in ("pyproject.toml", "examples/admission_demo.py", "src/probity_observer/__init__.py"):
        content = b"# checked source\n"
        target = root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
        pins[name] = hashlib.sha1(b"blob " + str(len(content)).encode() + b"\0" + content).hexdigest()
    monkeypatch.setattr(EXPERIMENT, "PINS", {"files": pins})
    return root, destination


class TestCaptureSources:
    class TestPassingCases:
        def test_copies_verified_bytes(self, sources: tuple[Path, Path]) -> None:
            root, destination = sources
            hashes = EXPERIMENT.capture_sources(root, destination)
            assert set(hashes) == set(EXPERIMENT.PINS["files"])
            for name, digest in hashes.items():
                assert (destination / name).read_bytes() == (root / name).read_bytes()
                assert digest == hashlib.sha256((root / name).read_bytes()).hexdigest()

    class TestFailingCases:
        @pytest.mark.parametrize("name", ["pyproject.toml", "examples/admission_demo.py", "src/probity_observer/__init__.py"])
        def test_changed_source_refused(self, sources: tuple[Path, Path], name: str) -> None:
            root, destination = sources
            (root / name).write_bytes(b"# substituted source\n")
            with pytest.raises(RuntimeError, match=f"^pinned observer source mismatch: {name}$"):
                EXPERIMENT.capture_sources(root, destination)

        @pytest.mark.parametrize("extra", ["unexpected.py", "submodule/hidden.py"])
        def test_extra_package_source_refused(self, sources: tuple[Path, Path], extra: str) -> None:
            root, destination = sources
            target = root / "src" / "probity_observer" / extra
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text("raise RuntimeError('untrusted import')\n", encoding="utf-8")
            with pytest.raises(RuntimeError, match="^observer package source set differs from the pins$"):
                EXPERIMENT.capture_sources(root, destination)
            assert not destination.exists()

        def test_missing_package_source_refused(self, sources: tuple[Path, Path]) -> None:
            root, destination = sources
            (root / "src/probity_observer/__init__.py").unlink()
            with pytest.raises(RuntimeError, match="^observer package source set differs from the pins$"):
                EXPERIMENT.capture_sources(root, destination)


class TestCheckManifest:
    class TestPassingCases:
        @given(content=st.binary(max_size=256))
        def test_exact_bytes_pass(self, content: bytes) -> None:
            import tempfile
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                bundle = root / "bundle"
                bundle.mkdir()
                (bundle / "packet.json").write_bytes(content)
                manifest = root / "manifest.json"
                manifest.write_text(json.dumps({"fileSha256": {"packet.json": hashlib.sha256(content).hexdigest()}}), encoding="utf-8")
                EXPERIMENT.check_manifest(bundle, manifest)

    class TestFailingCases:
        @pytest.mark.parametrize("mutation", ["change", "add", "remove"])
        def test_bundle_mutation_refused(self, tmp_path: Path, mutation: str) -> None:
            bundle = tmp_path / "bundle"
            bundle.mkdir()
            file = bundle / "packet.json"
            file.write_bytes(b"original")
            manifest = tmp_path / "manifest.json"
            manifest.write_text(json.dumps({"fileSha256": {"packet.json": hashlib.sha256(b"original").hexdigest()}}), encoding="utf-8")
            if mutation == "change":
                file.write_bytes(b"changed")
            elif mutation == "add":
                (bundle / "extra.json").write_bytes(b"extra")
            else:
                file.unlink()
            with pytest.raises(RuntimeError, match="^retained bundle differs from its file manifest$"):
                EXPERIMENT.check_manifest(bundle, manifest)


class TestRequireRefusal:
    class TestPassingCases:
        @given(reason=st.text(alphabet=st.characters(min_codepoint=32, max_codepoint=126), min_size=1, max_size=80))
        def test_exact_refusal_passes(self, reason: str) -> None:
            def refuse() -> None:
                raise ValueError(reason)
            assert EXPERIMENT.require_refusal(refuse, ValueError, reason) == reason

    class TestFailingCases:
        def test_success_is_not_a_refusal(self) -> None:
            with pytest.raises(RuntimeError, match="^observer unexpectedly admitted a negative control$"):
                EXPERIMENT.require_refusal(lambda: {"status": "admitted"}, ValueError, "refused")

        def test_unrelated_error_propagates(self) -> None:
            def fail() -> None:
                raise OSError("storage unavailable")
            with pytest.raises(OSError, match="^storage unavailable$"):
                EXPERIMENT.require_refusal(fail, ValueError, "refused")

        def test_wrong_reason_logged_and_refused(self, caplog: pytest.LogCaptureFixture) -> None:
            def refuse() -> None:
                raise ValueError("different refusal")
            with caplog.at_level(logging.ERROR, logger="atlas.observer_admission"):
                with pytest.raises(RuntimeError, match="^observer refusal differs from the expected reason$"):
                    EXPERIMENT.require_refusal(refuse, ValueError, "expected refusal")
            assert caplog.messages == ["unexpected refusal reason: different refusal"]
