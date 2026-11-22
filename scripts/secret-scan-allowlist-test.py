"""The corpus allowlist covers the fixture shapes and nothing wider.

Each case writes a scratch repository carrying the repository's .gitleaks.toml, commits one file,
and runs scripts/secret-scan.sh over it. The fixture shapes must scan clean; the same field with
a realistic secret, or the fixture shape in another place, must still fail.

A public key passes only when three things hold together: a corpus or fixture directory, a field
name that ends in a public-key term (or the exact member issuerKey, or key in a TRUST.json trust
root), and a value that decodes to exactly 32 bytes. A 32-byte secret has a public key's size,
so the name and the directory are what separate them; a 64-byte private key, a value of any other
length, a non-canonical encoding, a name without a public-key term, a public-key name that also
says private, and the same line outside a corpus directory must all still fail.
"""

from __future__ import annotations

import base64
import hashlib
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
KEY = "k" + "ey"
# A 64-byte Ed25519 private key (seed then public half), built here, never a literal. A
# hash output, not an arithmetic run: gitleaks drops a value whose text holds one of its
# stopwords, and a run of evenly spaced bytes encodes to one often enough to pass a case.
PRIVATE_64 = hashlib.sha512(b"ed25519 private key: seed then public half").digest()
B64URL_32 = base64.urlsafe_b64encode(bytes((i * 41 + 3) % 256 for i in range(2 * 16))).decode().rstrip("=")
HEX_32 = bytes((i * 23 + 19) % 256 for i in range(2 * 16)).hex()
TRUST = "corpora/vectors-actor-marker-survival/TRUST.json"


def _scan(tmp_path: Path, relpath: str, text: str) -> int:
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
    return subprocess.run(argv, capture_output=True, check=False).returncode


CTX = "corpora/vectors-agent-card-receipt/cases/accept-x/context.json"
STMT = "corpora/vectors-credential-release/cases/credential-carries-secret/statement.json"


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
        # issuerKey is the issuer's public key by the suites' definition: any 32-byte value
        # passes in a case file, so a new suite needs no new pin.
        (CTX, f'{{\n  "issuerKey": "{REAL_B64}",\n  "now": "2026-10-27T12:00:00Z"\n}}\n'),
        ("corpora/vectors-x/cases/a/case.json", f'{{\n  "verifying{KEY.title()}": "{B64URL_32}"\n}}\n'),
        ("vectors/statements/v1.json", f'{{"embeddedVerification{KEY.title()}": "{HEX_32}"}}\n'),
        ("interop/x/fixtures/w.json", f'{{\n  "signer_public_{KEY}_hex": "{HEX_32}"\n}}\n'),
        (TRUST, f'{{"writers": {{"agent": {{\n  "{KEY}": "{B64URL_32}",\n  "role": "agent"}}}}}}\n'),
    ],
)
def test_the_fixture_shapes_scan_clean(tmp_path: Path, relpath: str, text: str) -> None:
    assert _scan(tmp_path, relpath, text) == 0


@pytest.mark.parametrize(
    ("relpath", "text"),
    [
        (CTX, f'{{\n  "issuerKey": "{base64.b64encode(PRIVATE_64).decode()}"\n}}\n'),
        (CTX, f'{{\n  "public{KEY.title()}": "{PRIVATE_64.hex()}"\n}}\n'),
        (CTX, f'{{\n  "issuerKey": "{REAL_B64[:-2]}B="\n}}\n'),
        (CTX, f'{{\n  "private{KEY.title()}": "{REAL_B64}"\n}}\n'),
        (CTX, f'{{\n  "issuer_{KEY}": "{REAL_B64}"\n}}\n'),
        (CTX, f'{{\n  "seed_public_{KEY}": "{REAL_B64}"\n}}\n'),
        (TRUST, f'{{\n  "{KEY}": "{base64.b64encode(PRIVATE_64).decode()}"\n}}\n'),
        ("src/config.json", f'{{\n  "issuerKey": "{PUBLIC_KEY}"\n}}\n'),
        ("src/config.json", f'{{\n  "verifying{KEY.title()}": "{B64URL_32}"\n}}\n'),
        ("src/config.json", f'{{\n  "public{KEY.title()}": "{PRIVATE_64.hex()}"\n}}\n'),
        ("src/config.json", f'{{\n  "public_{KEY}_seed": "{REAL_B64}"\n}}\n'),
        ("src/client.py", f'signing_{KEY} = "{HEX_32}"\n'),
        (STMT, f'{{\n  "credential": {{\n    "token": "{REAL_JWT}"\n  }}\n}}\n'),
        ("src/client.py", f'cred = dict(token="{EMPTY_JWT}")\n'),
        ("src/client.py", 'api_key = "%s"\n' % ("ghp_" + "a1B2c3D4e5F6g7H8i9J0" * 2)),
    ],
)
def test_a_realistic_secret_or_a_misplaced_fixture_still_fails(
    tmp_path: Path, relpath: str, text: str
) -> None:
    assert _scan(tmp_path, relpath, text) == 1
