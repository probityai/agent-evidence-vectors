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
import json
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
KEY = "k" + "ey"
# A 64-byte Ed25519 private key (seed then public half), built here, never a literal. A
# hash output, not an arithmetic run: gitleaks drops a value whose text holds one of its
# stopwords, and a run of evenly spaced bytes encodes to one often enough to pass a case.
PRIVATE_64 = hashlib.sha512(b"ed25519 private key: seed then public half").digest()
B64URL_32 = base64.urlsafe_b64encode(bytes((i * 41 + 3) % 256 for i in range(2 * 16))).decode().rstrip("=")
HEX_32 = bytes((i * 23 + 19) % 256 for i in range(2 * 16)).hex()
TRUST = "corpora/vectors-actor-marker-survival/TRUST.json"


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
JWS_PATH = "corpora/vectors-principal-binding/cases/uma-bound/binding.jws"
# The committed agreement: a JWS whose header names the published agent test key.
AGREEMENT = (ROOT / JWS_PATH).read_text()
DNS_AID = "corpora/vectors-dns-aid-sig-v01/cases/full-coverage-valid.json"
_DNS_AID_CASE = json.loads((ROOT / DNS_AID).read_text(encoding="utf-8"))
DNS_AID_SIG = _DNS_AID_CASE["sig"]
DNS_AID_X = _DNS_AID_CASE["jwks"]["keys"][0]["x"]
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
        # issuerKey is the issuer's public key by the suites' definition: any 32-byte value
        # passes in a case file, so a new suite needs no new pin.
        (CTX, f'{{\n  "issuerKey": "{REAL_B64}",\n  "now": "2026-10-27T12:00:00Z"\n}}\n'),
        ("corpora/vectors-x/cases/a/case.json", f'{{\n  "verifying{KEY.title()}": "{B64URL_32}"\n}}\n'),
        ("vectors/statements/v1.json", f'{{"embeddedVerification{KEY.title()}": "{HEX_32}"}}\n'),
        ("interop/x/fixtures/w.json", f'{{\n  "signer_public_{KEY}_hex": "{HEX_32}"\n}}\n'),
        ("packages/admission/rego/corpus_vectors.json", f'{{"embeddedVerification{KEY.title()}": "{HEX_32}"}}\n'),
        (TRUST, f'{{"writers": {{"agent": {{\n  "{KEY}": "{B64URL_32}",\n  "role": "agent"}}}}}}\n'),
        (JWS_PATH, AGREEMENT),
        (DNS_AID,
         f'{{\n "jwks": {{"keys": [{{"x": "{DNS_AID_X}"}}]}},\n'
         f' "sig": "{DNS_AID_SIG}"\n}}\n'),
        (PRINCIPAL,
         f'{{\n  "producerKey": "{PRODUCER_KEY}",\n  "now": "2026-11-10T12:00:00Z"\n}}\n'),
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
        ("scripts/probe-test.py", f'OTHER_{KEY.upper()} = "{HEX_32}"\n'),
        (STMT, f'{{\n  "credential": {{\n    "token": "{REAL_JWT}"\n  }}\n}}\n'),
        ("src/client.py", f'cred = dict(token="{EMPTY_JWT}")\n'),
        ("src/record.json", f'{{\n "sig": "{DNS_AID_SIG}"\n}}\n'),
        ("src/client.py", 'api_key = "%s"\n' % ("ghp_" + "a1B2c3D4e5F6g7H8i9J0" * 2)),
        (JWS_PATH, REAL_JWT + "\n"),
        ("src/agreement.jws", AGREEMENT),
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
