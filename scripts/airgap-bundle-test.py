"""Tests for the offline bundle: build from a hash-pinned lock, verify, install with no network.

The wheel under test is a small stand-in carrying the same layout as the real one (the rail
entry point and a corpora directory), served from a local directory as the only index. The
install runs with every network route pointed at a closed port, so a stray fetch fails the test
instead of reaching the internet. The workflow also runs the real wheel through the same steps.
"""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import os
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("airgap_bundle", ROOT / "scripts/airgap-bundle.py")
assert _spec and _spec.loader
airgap = importlib.util.module_from_spec(_spec)
sys.modules["airgap_bundle"] = airgap
_spec.loader.exec_module(airgap)

VERSION = "9.9.9"
WHEEL = f"agent_evidence_vectors-{VERSION}-py3-none-any.whl"
RAIL = """
import sys


def main():
    args = sys.argv[1:]
    if "--list-corpora" in args:
        print("vectors")
        return 0
    if "--report" in args:
        open(args[args.index("--report") + 1], "w").write("{}")
    print("demo run complete")
    return 0
"""


def make_wheel(directory: Path) -> Path:
    members = {
        "agent_evidence_vectors/__init__.py": "",
        "agent_evidence_vectors/run_vectors.py": RAIL,
        "agent_evidence_vectors/corpora/vectors/MANIFEST.json": '{"suite": "demo"}\n',
        "agent_evidence_vectors/corpora/vectors/accept/a.json": '{"id": "a"}\n',
        "agent_evidence_vectors/corpora/vectors/bytes/SHA256SUMS": "a corpus's own list\n",
        f"agent_evidence_vectors-{VERSION}.dist-info/METADATA": (
            f"Metadata-Version: 2.1\nName: agent-evidence-vectors\nVersion: {VERSION}\n"
        ),
        f"agent_evidence_vectors-{VERSION}.dist-info/WHEEL": (
            "Wheel-Version: 1.0\nGenerator: test\nRoot-Is-Purelib: true\nTag: py3-none-any\n"
        ),
        f"agent_evidence_vectors-{VERSION}.dist-info/entry_points.txt": (
            "[console_scripts]\nagent-evidence-vectors = agent_evidence_vectors.run_vectors:main\n"
        ),
    }
    record = []
    for name, text in members.items():
        raw = text.encode()
        digest = base64.urlsafe_b64encode(hashlib.sha256(raw).digest()).rstrip(b"=").decode()
        record.append(f"{name},sha256={digest},{len(raw)}")
    record.append(f"agent_evidence_vectors-{VERSION}.dist-info/RECORD,,")
    members[f"agent_evidence_vectors-{VERSION}.dist-info/RECORD"] = "\n".join(record) + "\n"
    path = directory / WHEEL
    with zipfile.ZipFile(path, "w") as archive:
        for name, text in members.items():
            archive.writestr(name, text)
    return path


@pytest.fixture
def mirror(tmp_path: Path) -> Path:
    directory = tmp_path / "mirror"
    directory.mkdir()
    make_wheel(directory)
    return directory


def write_lock(path: Path, wheel: Path) -> Path:
    digest = airgap.sha256_file(wheel)
    path.write_text(
        f"agent-evidence-vectors=={VERSION} \\\n    --hash=sha256:{digest}\n", encoding="utf-8"
    )
    return path


def run_main(*argv: str) -> int:
    return int(airgap.main(list(argv)))


@pytest.fixture
def bundle(tmp_path: Path, mirror: Path) -> Path:
    lock = write_lock(tmp_path / "requirements.lock", mirror / WHEEL)
    out = tmp_path / "bundle"
    code = run_main(
        "build", "--lock", str(lock), "--out", str(out),
        "--no-index", "--find-links", str(mirror),
    )  # fmt: skip
    assert code == 0
    return out


def test_build_lays_out_wheels_corpora_sums_and_installer(bundle: Path):
    assert (bundle / "wheels" / WHEEL).is_file()
    assert (bundle / "corpora/vectors/MANIFEST.json").is_file()
    assert (bundle / "corpora/vectors/accept/a.json").is_file()
    assert (bundle / "install.sh").stat().st_mode & 0o111
    sums = (bundle / "SHA256SUMS").read_text()
    assert f"  wheels/{WHEEL}" in sums and "  corpora/vectors/MANIFEST.json" in sums
    assert "  SHA256SUMS" not in sums
    assert "  corpora/vectors/bytes/SHA256SUMS" in sums
    assert airgap.verify(bundle) == []


def test_verify_names_a_changed_missing_and_extra_file(bundle: Path):
    (bundle / "corpora/vectors/accept/a.json").write_text("{}")
    (bundle / "corpora/vectors/MANIFEST.json").unlink()
    (bundle / "stray.txt").write_text("x")
    assert airgap.verify(bundle) == [
        "missing: corpora/vectors/MANIFEST.json",
        "changed: corpora/vectors/accept/a.json",
        "extra: stray.txt",
    ]
    assert run_main("verify", str(bundle)) == 1


def test_verify_refuses_a_bundle_with_no_sums(tmp_path: Path):
    assert airgap.verify(tmp_path) == ["SHA256SUMS is missing"]


def test_a_wrong_hash_in_the_lock_stops_the_build(tmp_path: Path, mirror: Path):
    lock = tmp_path / "requirements.lock"
    lock.write_text(f"agent-evidence-vectors=={VERSION} --hash=sha256:{'0' * 64}\n")
    code = run_main(
        "build", "--lock", str(lock), "--out", str(tmp_path / "b"),
        "--no-index", "--find-links", str(mirror),
    )  # fmt: skip
    assert code == 2


@pytest.mark.parametrize(
    "line",
    [
        "agent-evidence-vectors>=1.0 --hash=sha256:" + "a" * 64,
        f"agent-evidence-vectors=={VERSION}",
        f"agent-evidence-vectors=={VERSION} --hash=sha256:abc",
    ],
)
def test_a_lock_line_without_an_exact_pin_and_hash_is_refused(tmp_path: Path, line: str):
    lock = tmp_path / "bad.lock"
    lock.write_text(line + "\n")
    with pytest.raises(airgap.BundleError):
        airgap.read_lock(lock)


def test_an_empty_lock_is_refused(tmp_path: Path):
    lock = tmp_path / "empty.lock"
    lock.write_text("# nothing\n")
    with pytest.raises(airgap.BundleError):
        airgap.read_lock(lock)


def test_build_refuses_a_non_empty_output_directory(tmp_path: Path, mirror: Path):
    lock = write_lock(tmp_path / "requirements.lock", mirror / WHEEL)
    out = tmp_path / "out"
    out.mkdir()
    (out / "keep").write_text("x")
    assert run_main("build", "--lock", str(lock), "--out", str(out), "--no-index",
                    "--find-links", str(mirror)) == 2  # fmt: skip


def test_a_wheel_member_that_escapes_the_corpora_directory_is_refused(tmp_path: Path):
    wheels = tmp_path / "wheels"
    wheels.mkdir()
    with zipfile.ZipFile(wheels / WHEEL, "w") as archive:
        archive.writestr("agent_evidence_vectors/corpora/../../evil.txt", "x")
    with pytest.raises(airgap.BundleError):
        airgap.unpack_corpora(wheels, tmp_path / "corpora")


def test_the_tarball_carries_its_own_digest(tmp_path: Path, mirror: Path):
    lock = write_lock(tmp_path / "requirements.lock", mirror / WHEEL)
    out = tmp_path / "aev-airgap-9.9.9"
    assert run_main("build", "--lock", str(lock), "--out", str(out), "--no-index",
                    "--find-links", str(mirror), "--tar") == 0  # fmt: skip
    tarball = tmp_path / "aev-airgap-9.9.9.tar.gz"
    recorded = (tmp_path / "aev-airgap-9.9.9.tar.gz.sha256").read_text().split()[0]
    assert recorded == airgap.sha256_file(tarball)


def offline_env() -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if not k.lower().endswith("_proxy")}
    dead = "http://127.0.0.1:9"
    env.update(
        PYTHON=sys.executable,
        PIP_INDEX_URL=f"{dead}/simple",
        HTTP_PROXY=dead,
        HTTPS_PROXY=dead,
        http_proxy=dead,
        https_proxy=dead,
    )
    return env


def install(bundle: Path, target: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["sh", str(bundle / "install.sh"), str(target)],
        capture_output=True, text=True, env=offline_env(), check=False, timeout=300,
    )  # fmt: skip


def test_install_into_a_fresh_venv_with_every_network_route_dead(bundle: Path, tmp_path: Path):
    target = tmp_path / "venv"
    done = install(bundle, target)
    assert done.returncode == 0, done.stderr + done.stdout
    assert "demo run complete" in done.stdout
    listed = subprocess.run(
        [str(target / "bin/agent-evidence-vectors"), "--list-corpora"],
        capture_output=True, text=True, check=True,
    )  # fmt: skip
    assert listed.stdout.split() == ["vectors"]


def test_install_stops_before_pip_when_a_wheel_was_tampered(bundle: Path, tmp_path: Path):
    wheel = bundle / "wheels" / WHEEL
    wheel.write_bytes(wheel.read_bytes() + b"\0")
    target = tmp_path / "venv"
    done = install(bundle, target)
    assert done.returncode != 0
    assert not target.exists()


def test_install_stops_when_a_corpus_file_was_tampered(bundle: Path, tmp_path: Path):
    (bundle / "corpora/vectors/accept/a.json").write_text('{"id": "forged"}')
    done = install(bundle, tmp_path / "venv")
    assert done.returncode != 0 and not (tmp_path / "venv").exists()


def test_the_installer_refuses_an_unhashed_requirement(bundle: Path, tmp_path: Path):
    """pip's own --require-hashes check backs the bundle's sums: a lock edited to drop the hash,
    with the sums regenerated, still does not install."""
    (bundle / "requirements.lock").write_text(f"agent-evidence-vectors=={VERSION}\n")
    airgap.write_sums(bundle)
    done = install(bundle, tmp_path / "venv")
    assert done.returncode != 0


def test_release_dir_carries_the_signed_digest_list(tmp_path: Path, mirror: Path):
    release = tmp_path / "release"
    release.mkdir()
    for name in (
        "CORPUS-DIGESTS.txt",
        "CORPUS-DIGESTS.txt.sig",
        "cosign.pub",
        "CORPUS-DIGESTS.txt.sig.ots",
    ):
        (release / name).write_text(name)
    lock = write_lock(tmp_path / "requirements.lock", mirror / WHEEL)
    out = tmp_path / "bundle"
    assert run_main("build", "--lock", str(lock), "--out", str(out), "--no-index",
                    "--find-links", str(mirror), "--release-dir", str(release)) == 0  # fmt: skip
    assert (out / "release/cosign.pub").read_text() == "cosign.pub"
    assert not (out / "release/CORPUS-DIGESTS.txt.sig.tsr").exists()
    assert "  release/CORPUS-DIGESTS.txt.sig" in (out / "SHA256SUMS").read_text()


def test_a_release_dir_missing_the_signature_stops_the_build(tmp_path: Path, mirror: Path):
    release = tmp_path / "release"
    release.mkdir()
    (release / "CORPUS-DIGESTS.txt").write_text("x")
    lock = write_lock(tmp_path / "requirements.lock", mirror / WHEEL)
    assert run_main("build", "--lock", str(lock), "--out", str(tmp_path / "b"), "--no-index",
                    "--find-links", str(mirror), "--release-dir", str(release)) == 2  # fmt: skip
