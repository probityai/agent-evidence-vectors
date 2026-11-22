"""Judge one RSASSA-PKCS1-v1_5 SHA-256 signature by its whole recovered block.

A verifier that strips the padding and compares only the trailing 32 bytes with the digest accepts
any block that ends in the digest: arbitrary bytes between the padding and the digest, bytes
appended after a DigestInfo prefix, another hash algorithm's OID carrying a 32-byte value, or a
padding string shorter than the modulus requires. This reader recovers the block and compares it,
byte for byte, with the two encodings that exist:

- ``valid`` / ``rfc8017``: the RFC 8017 encoding, SHA-256 DigestInfo with NULL parameters;
- ``profile-dependent`` / ``absent_null_parameters``: the same DigestInfo with the NULL parameters
  omitted, the form some signers emit; whether to accept it is the consumer's profile;
- ``invalid`` / ``block_not_exact_encoding``: any other block, including every block that only
  ends in the digest;
- ``invalid`` / ``signature_length``: a signature that is not exactly the modulus length, or not
  below the modulus.

The external-verifier contract: ``<verifier> <case-dir>/record.json --json`` prints one JSON object
carrying ``decision`` and ``reason``; exit 0 for ``valid``, 1 for ``invalid``, 2 for
``profile-dependent``.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import shlex
import subprocess
from pathlib import Path
from typing import Any

from agent_evidence_vectors import strictjson
from agent_evidence_vectors.monitorcoverage import _fixture_error, _validated_entries, run_corpus

SUITE = "rsa-digestinfo/v1"
EXIT_FOR = {"valid": 0, "invalid": 1, "profile-dependent": 2}
SHA256_DIGEST_INFO = bytes.fromhex("3031300d060960864801650304020105000420")
SHA256_DIGEST_INFO_ABSENT_PARAMS = bytes.fromhex("302f300b06096086480165030402010420")
_HERE = Path(__file__).resolve().parent
ROOT = (
    _HERE / "corpora" / "vectors-rsa-digestinfo"
    if (_HERE / "corpora").exists()
    else _HERE.parents[1] / "corpora" / "vectors-rsa-digestinfo"
)


def b64u_int(text: str) -> int:
    return int.from_bytes(base64.urlsafe_b64decode(text + "=" * (-len(text) % 4)), "big")


def block(t: bytes, k: int) -> bytes:
    """The full-length EMSA-PKCS1-v1_5 block around ``t``."""
    return b"\x00\x01" + b"\xff" * (k - len(t) - 3) + b"\x00" + t


def judge(record: dict[str, Any]) -> dict[str, str]:
    n, e = b64u_int(record["key"]["n"]), b64u_int(record["key"]["e"])
    k = (n.bit_length() + 7) // 8
    sig = base64.urlsafe_b64decode(record["signature"] + "=" * (-len(record["signature"]) % 4))
    s = int.from_bytes(sig, "big")
    if len(sig) != k or s >= n:
        return {"decision": "invalid", "reason": "signature_length"}
    recovered = pow(s, e, n).to_bytes(k, "big")
    digest = hashlib.sha256(record["message"].encode("utf-8")).digest()
    if recovered == block(SHA256_DIGEST_INFO + digest, k):
        return {"decision": "valid", "reason": "rfc8017"}
    if recovered == block(SHA256_DIGEST_INFO_ABSENT_PARAMS + digest, k):
        return {"decision": "profile-dependent", "reason": "absent_null_parameters"}
    return {"decision": "invalid", "reason": "block_not_exact_encoding"}


def verify(record_path: Path) -> dict[str, str]:
    return judge(strictjson.loads(record_path.read_text(encoding="utf-8")))


def _external(command: list[str], path: Path) -> tuple[bool, dict[str, Any] | str]:
    try:
        result = subprocess.run(
            [*command, str(path), "--json"], capture_output=True, text=True, timeout=90, check=False
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, f"verifier did not run: {exc}"
    try:
        answer = strictjson.loads(result.stdout)
        observed = {key: answer[key] for key in ("decision", "reason")}
    except (ValueError, KeyError, TypeError):
        return True, f"verifier returned no decision (exit {result.returncode})"
    if EXIT_FOR.get(str(observed["decision"])) != result.returncode:
        return True, f"exit {result.returncode} disagrees with decision {observed['decision']}"
    return True, observed


def check(verifier: str | list[str] | None = None, root: Path = ROOT) -> tuple[int, list[str]]:
    """Check every case through the named verifier or the reference reader."""
    try:
        entries, manifest_error = _validated_entries(root, SUITE)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        return 0, [f"invalid corpus: {exc}"]
    if manifest_error:
        return 0, [manifest_error]
    command = shlex.split(verifier) if isinstance(verifier, str) else verifier
    if command is not None and not command:
        return 0, ["verifier command is empty"]
    errors: list[str] = []
    answered = 0
    for entry in entries:
        name, directory = entry["id"], root / entry["path"]
        fixture_error = _fixture_error(directory, entry)
        if fixture_error:
            errors.append(f"{name}: {fixture_error}")
            continue
        path = directory / "record.json"
        ran, observed = (True, verify(path)) if command is None else _external(command, path)
        answered += int(ran)
        if isinstance(observed, str):
            errors.append(f"{name}: {observed}")
        elif observed != entry["expected"]:
            errors.append(f"{name}: expected {entry['expected']}, got {observed}")
    return answered, errors


def run(root: str, verifier: list[str] | None, report_path: str, rail_note: str) -> int:
    return run_corpus(SUITE, check, root, verifier, report_path, rail_note)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or SUITE).splitlines()[0])
    parser.add_argument("record", nargs="?", help="judge one record.json with the reference reader")
    parser.add_argument("--json", action="store_true", help="print the decision as JSON")
    parser.add_argument("--verifier", help="run every record through this verifier instead")
    args = parser.parse_args(argv)
    if args.record:
        answer = verify(Path(args.record))
        print(
            json.dumps(answer, sort_keys=True)
            if args.json
            else f"{answer['decision']} {answer['reason']}"
        )
        return EXIT_FOR[answer["decision"]]
    answered, errors = check(args.verifier)
    for error in errors:
        print(error)
    total = len(strictjson.loads((ROOT / "MANIFEST.json").read_text(encoding="utf-8"))["vectors"])
    print(f"answered {answered} of {total} cases")
    return 1 if errors or answered != total else 0


if __name__ == "__main__":
    raise SystemExit(main())
