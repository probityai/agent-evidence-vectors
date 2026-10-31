"""Independent transport faults must not become qualified fixture inputs."""

import copy
import hashlib
import json
import shutil
import urllib.error

import pytest

import fetch_inputs
from json_profile import Refusal
from replay import HERE, load_cases


def empty_root(tmp_path):
    shutil.copy2(HERE / "INPUT-MANIFEST.json", tmp_path / "INPUT-MANIFEST.json")
    return tmp_path


def bytes_for(url, maximum):
    return (HERE / "private-inputs" / url.rsplit("/", 1)[1]).read_bytes()


def test_pinned_fetch_is_complete_then_refuses_to_overwrite(tmp_path):
    root = empty_root(tmp_path)
    assert fetch_inputs.fetch(root, bytes_for) == 12
    assert len(load_cases(root)[2]) == 12
    with pytest.raises(Refusal, match="input_directory_already_exists"):
        fetch_inputs.fetch(root, bytes_for)


@pytest.mark.parametrize("fault", ("size", "digest", "network"))
def test_single_transport_fault_never_publishes_a_partial_population(tmp_path, fault):
    root = empty_root(tmp_path)

    def corrupt(url, maximum):
        data = bytes_for(url, maximum)
        if fault == "network":
            raise Refusal("input_fetch_failed")
        return data + b"\n" if fault == "size" else b"x" + data[1:]

    with pytest.raises(Refusal):
        fetch_inputs.fetch(root, corrupt)
    assert not (root / "private-inputs").exists()
    assert not list(root.glob(".trace-fetch-*"))


def test_manifest_substitution_cannot_rebaseline_the_cases(tmp_path):
    root = empty_root(tmp_path)
    manifest = json.loads((root / "INPUT-MANIFEST.json").read_bytes())
    changed = copy.deepcopy(manifest)
    changed["upstream_commit"] = "0" * 40
    (root / "INPUT-MANIFEST.json").write_text(json.dumps(changed))
    assert (
        hashlib.sha256((root / "INPUT-MANIFEST.json").read_bytes()).hexdigest()
        != fetch_inputs.FROZEN_INPUT_MANIFEST
    )
    with pytest.raises(Refusal, match="input_manifest_changed"):
        fetch_inputs.fetch(root, bytes_for)
    with pytest.raises(Refusal, match="input_manifest_changed"):
        load_cases(root)


def test_symlink_input_destination_is_refused(tmp_path):
    root = empty_root(tmp_path)
    (root / "private-inputs").symlink_to(tmp_path / "missing-directory", target_is_directory=True)
    with pytest.raises(Refusal, match="input_directory_already_exists"):
        fetch_inputs.fetch(root, bytes_for)


def test_another_fetch_cannot_publish_into_the_same_destination(tmp_path):
    root = empty_root(tmp_path)
    lock = root / ".trace-fetch-lock"
    lock.mkdir()
    with pytest.raises(Refusal, match="input_fetch_locked"):
        fetch_inputs.fetch(root, bytes_for)
    assert lock.is_dir()
    assert not (root / "private-inputs").exists()


def test_redirect_and_network_failure_are_refused(monkeypatch):
    with pytest.raises(Refusal, match="input_fetch_redirect_refused"):
        fetch_inputs.RefuseRedirect().redirect_request(
            None, None, 302, "", {}, "https://example.test/"
        )

    class Failed:
        def open(self, *args, **kwargs):
            raise urllib.error.URLError("synthetic network refusal")

    monkeypatch.setattr(fetch_inputs.urllib.request, "build_opener", lambda *args: Failed())
    with pytest.raises(Refusal, match="input_fetch_failed"):
        fetch_inputs.download("https://example.test/", 1)


def test_download_reads_only_the_expected_size_plus_one(monkeypatch):
    class Response:
        status = 200
        url = "https://example.test/frozen"

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self, maximum):
            assert maximum == 6
            return b"frozen"

    class Opener:
        def open(self, url, timeout):
            assert url == Response.url and timeout == 30
            return Response()

    monkeypatch.setattr(fetch_inputs.urllib.request, "build_opener", lambda *args: Opener())
    assert fetch_inputs.download(Response.url, 5) == b"frozen"


def test_native_fetch_command_uses_the_frozen_population(tmp_path, monkeypatch):
    root = empty_root(tmp_path)
    original = fetch_inputs.fetch
    monkeypatch.setattr(fetch_inputs, "fetch", lambda chosen: original(chosen, bytes_for))
    monkeypatch.setattr("sys.argv", ["fetch_inputs.py", "--root", str(root)])
    assert fetch_inputs.main() == 0
