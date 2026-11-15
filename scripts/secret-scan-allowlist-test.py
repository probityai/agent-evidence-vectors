"""The corpus allowlist covers the card-receipt and credential-release fixtures and nothing wider.

Each case writes a scratch repository carrying the repository's .gitleaks.toml, commits one file,
and runs scripts/secret-scan.sh over it. The fixture shapes must scan clean; the same field with
a realistic secret, or the fixture shape in another place, must still fail.
"""

from __future__ import annotations

import base64
import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCAN = ROOT / "scripts" / "secret-scan.sh"
GIT_ENV = {
    **os.environ,
    "GIT_AUTHOR_NAME": "t",
    "GIT_AUTHOR_EMAIL": "t@example.invalid",
    "GIT_COMMITTER_NAME": "t",
    "GIT_COMMITTER_EMAIL": "t@example.invalid",
}
PUBLIC_KEY = "Ob6mHCtjckbIra26o4A/wgoaPfjBID6naeJBKAYZc5E="
# The producer public key of the principal-action cases, kept as the 64-hex form the repository
# allowlist already covers so that no base64 key literal sits in this file.
PRODUCER_KEY_HEX = "a566e22954e9af7e0f45999600f3fda371187d53af1af449d3da82e032f1f5ec"
PRODUCER_KEY = base64.b64encode(bytes.fromhex(PRODUCER_KEY_HEX)).decode()
EMPTY_JWT = "eyJhbGciOiJub25lIn0.e30."
# A high-entropy 256-bit value that is not a published test key (a stand-in for a real secret).
REAL_B64 = base64.b64encode(bytes((i * 37 + 11) % 256 for i in range(2 * 16))).decode()
# Built here so no secret-shaped literal sits in the file.
REAL_JWT = ".".join(
    [
        base64.urlsafe_b64encode(b'{"alg":"HS256"}').rstrip(b"=").decode(),
        base64.urlsafe_b64encode(b'{"sub":"user-42","role":"admin"}').rstrip(b"=").decode(),
        base64.urlsafe_b64encode(bytes((i * 29 + 5) % 256 for i in range(2 * 16)))
        .rstrip(b"=")
        .decode(),
    ]
)
DIGEST = "4badc4f0c891b654107a33eb52b94a3d31ef3bd9dbba322958019ad1a9cc07bb"


def _scan_run(tmp_path: Path, relpath: str, text: str) -> subprocess.CompletedProcess[bytes]:
    work = tmp_path / "repo"
    work.mkdir()
    git = lambda *a: subprocess.run(  # noqa: E731
        ["git", "-C", str(work), *a], check=True, capture_output=True, env=GIT_ENV
    )
    git("init", "-q", "-b", "main")
    shutil.copy(ROOT / ".gitleaks.toml", work / ".gitleaks.toml")
    target = work / relpath
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text)
    git("add", ".")
    git("commit", "-q", "-m", "fixture")
    argv = ["bash", str(SCAN), "--repo", str(work), "--config", str(work / ".gitleaks.toml")]
    return subprocess.run(argv, capture_output=True, check=False)


def _scan(tmp_path: Path, relpath: str, text: str) -> int:
    return _scan_run(tmp_path, relpath, text).returncode


CTX = "corpora/vectors-agent-card-receipt/cases/accept-x/context.json"
STMT = "corpora/vectors-credential-release/cases/credential-carries-secret/statement.json"
PRINCIPAL = "corpora/vectors-principal-action/cases/basic-user-agent-act-absent/case.json"


@pytest.mark.parametrize(
    ("relpath", "text"),
    [
        (CTX, f'{{\n  "issuerKey": "{PUBLIC_KEY}",\n  "now": "2026-10-27T12:00:00Z"\n}}\n'),
        (STMT, f'{{\n  "credential": {{\n    "token": "{EMPTY_JWT}"\n  }}\n}}\n'),
        (
            "corpora/vectors-credential-release/cases/credential-carries-token-hash/statement.json",
            f'{{\n  "credential": {{\n    "tokenSha256": "{DIGEST}"\n  }}\n}}\n',
        ),
        ("corpora/vectors-credential-release/gen_vectors.py",
         f'cred = dict(token="{EMPTY_JWT}")\n'),
        (PRINCIPAL, f'{{\n  "producerKey": "{PRODUCER_KEY}",\n  "now": "2026-11-10T12:00:00Z"\n}}\n'),
    ],
)
def test_the_fixture_shapes_scan_clean(tmp_path: Path, relpath: str, text: str) -> None:
    assert _scan(tmp_path, relpath, text) == 0


@pytest.mark.parametrize(
    ("relpath", "text"),
    [
        (CTX, f'{{\n  "issuerKey": "{REAL_B64}"\n}}\n'),
        ("src/config.json", f'{{\n  "issuerKey": "{PUBLIC_KEY}"\n}}\n'),
        (STMT, f'{{\n  "credential": {{\n    "token": "{REAL_JWT}"\n  }}\n}}\n'),
        ("src/client.py", f'cred = dict(token="{EMPTY_JWT}")\n'),
        ("src/client.py", 'api_key = "%s"\n' % ("ghp_" + "a1B2c3D4e5F6g7H8i9J0" * 2)),
        (PRINCIPAL, f'{{\n  "producerKey": "{REAL_B64}"\n}}\n'),
        ("src/config.json", f'{{\n  "producerKey": "{PRODUCER_KEY}"\n}}\n'),
    ],
)
def test_a_realistic_secret_or_a_misplaced_fixture_still_fails(
    tmp_path: Path, relpath: str, text: str
) -> None:
    assert _scan(tmp_path, relpath, text) == 1


def test_a_refused_scan_names_the_file_and_line_of_each_finding(tmp_path: Path) -> None:
    # The hook ends "gitleaks reports findings ... (see above)", so the scan has to print them.
    done = _scan_run(tmp_path, "src/config.json", f'{{\n  "producerKey": "{PRODUCER_KEY}"\n}}\n')
    assert done.returncode == 1
    report = (done.stdout + done.stderr).decode()
    assert "File:        src/config.json" in report
    assert "Line:        2" in report
    assert "RuleID:      generic-api-key" in report
    assert PRODUCER_KEY not in report
