"""Generate signed synthetic cases for the optional observed-effect code join.

The released corpus is an immutable source, never an output. These cases use
its published observer test key and baseline; they establish verifier behavior,
not native execution, capability issuer approval, or independent code capture.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
BASELINE = ROOT / "corpora/vectors-observed-effect/statements/v1c6fdd82db5229e4.json"
SEED = bytes.fromhex("00" * 31 + "11")
KEY = Ed25519PrivateKey.from_private_bytes(SEED)
CODE = b'print("observed-code-digest synthetic candidate")\n'
DIGEST = hashlib.sha256(CODE).hexdigest()
ABSENT = object()


def signed(statement: dict[str, Any]) -> dict[str, Any]:
    """Sign deterministic fixture bytes using the public corpus test key.

    Parameters
    ----------
    statement : dict[str, Any]
        Decoded synthetic in-toto statement. Its code-digest mutation is already
        applied. The inherited prior commitment binds its original interval.

    Returns
    -------
    dict[str, Any]
        A fresh DSSE envelope. Sorted JSON is sufficient for these fixed ASCII
        fixture values; this helper is not a general RFC 8785 implementation.
    """
    payload_type = "application/vnd.in-toto+json"
    payload = json.dumps(statement, sort_keys=True, separators=(",", ":")).encode()
    pae = b"DSSEv1 %d %s %d %s" % (len(payload_type), payload_type.encode(), len(payload), payload)
    template = json.loads(BASELINE.read_text())
    template["payload"] = base64.b64encode(payload).decode()
    template["signatures"][0]["sig"] = base64.b64encode(KEY.sign(pae)).decode()
    return template


def definitions() -> list[tuple[str, Any, str, str, list[str]]]:
    """Declare each mutation separately from the reader that will judge it."""
    return [
        ("legacy-absent", ABSENT, "", "valid", []),
        ("present-unrequested", {"sha256": DIGEST}, "", "valid", []),
        ("required-match", {"sha256": DIGEST}, DIGEST, "valid", []),
        ("required-absent", ABSENT, DIGEST, "invalid", ["code-digest-required"]),
        ("required-mismatch", {"sha256": "0" * 64}, DIGEST, "invalid", ["code-digest-mismatch"]),
        ("null-field", None, "", "malformed", ["code-digest-shape"]),
        ("string-field", DIGEST, "", "malformed", ["code-digest-shape"]),
        ("array-field", [], "", "malformed", ["code-digest-shape"]),
        ("empty-field", {}, "", "malformed", ["code-digest-shape"]),
        ("unknown-algorithm", {"sha1": "0" * 40}, "", "malformed", ["code-digest-shape"]),
        (
            "extra-algorithm",
            {"sha256": DIGEST, "sha1": "0" * 40},
            "",
            "malformed",
            ["code-digest-shape"],
        ),
        ("uppercase-value", {"sha256": DIGEST.upper()}, "", "malformed", ["code-digest-value"]),
        ("trailing-newline", {"sha256": DIGEST + "\n"}, "", "malformed", ["code-digest-value"]),
        ("short-value", {"sha256": DIGEST[:-1]}, "", "malformed", ["code-digest-value"]),
        ("nonhex-value", {"sha256": "g" * 64}, "", "malformed", ["code-digest-value"]),
        ("numeric-value", {"sha256": 23}, "", "malformed", ["code-digest-value"]),
        ("null-value", {"sha256": None}, "", "malformed", ["code-digest-value"]),
        (
            "invalid-consumer-pin",
            {"sha256": DIGEST},
            "BAD",
            "invalid",
            ["code-digest-policy-invalid"],
        ),
    ]


def make_case(
    case_id: str, value: Any, expected_pin: str, verdict: str, codes: list[str]
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Build a signed statement and a separate expected-result manifest row."""
    baseline = json.loads(BASELINE.read_text())
    statement = json.loads(base64.b64decode(baseline["payload"]))
    if value is not ABSENT:
        statement["predicate"]["codeDigest"] = value
    row = {
        "id": case_id,
        "file": f"fixtures/{case_id}.json",
        "expectedCodeDigest": expected_pin,
        "expected": {"verdict": verdict, "codes": codes},
    }
    return row, signed(statement)


def extra_cases() -> list[tuple[dict[str, Any], dict[str, Any]]]:
    """Keep subject integrity and signed-payload integrity distinct from joining."""
    row, envelope = make_case("required-match", {"sha256": DIGEST}, DIGEST, "valid", [])
    statement = json.loads(base64.b64decode(envelope["payload"]))
    outputs = []
    for name, subjects, code in [
        (
            "code-replaces-after-root",
            [{"name": "code", "digest": {"sha256": DIGEST}}],
            "subject-not-the-after-root",
        ),
        (
            "code-is-second-subject",
            statement["subject"] + [{"name": "code", "digest": {"sha256": DIGEST}}],
            "subject-not-a-single-member",
        ),
    ]:
        altered = copy.deepcopy(statement)
        altered["subject"] = subjects
        outputs.append(
            (
                {
                    **row,
                    "id": name,
                    "file": f"fixtures/{name}.json",
                    "expected": {"verdict": "malformed", "codes": [code]},
                },
                signed(altered),
            )
        )
    statement["predicate"]["codeDigest"]["sha256"] = "0" * 64
    envelope["payload"] = base64.b64encode(
        json.dumps(statement, sort_keys=True, separators=(",", ":")).encode()
    ).decode()
    outputs.append(
        (
            {
                **row,
                "id": "unsigned-code-change",
                "file": "fixtures/unsigned-code-change.json",
                "expectedCodeDigest": "",
                "expected": {"verdict": "invalid", "codes": ["envelope-signature-invalid"]},
            },
            envelope,
        )
    )
    return outputs


def main() -> None:
    """Write only the candidate directory's deterministic fixture artifacts."""
    pairs = [make_case(*definition) for definition in definitions()] + extra_cases()
    rows = []
    for row, envelope in pairs:
        raw = (json.dumps(envelope, indent=2) + "\n").encode()
        (HERE / row["file"]).write_bytes(raw)
        rows.append({**row, "sha256": hashlib.sha256(raw).hexdigest()})
    (HERE / "synthetic-code.txt").write_bytes(CODE)
    manifest = {
        "profile": "observed-code-digest-candidate-v1",
        "status": "candidate",
        "classification": "same-author synthetic conformance cases; published test keys",
        "baseCommit": "beb47f330793c6be19e75d78098abb3ec2f12a1d",
        "baseStatement": "corpora/vectors-observed-effect/statements/v1c6fdd82db5229e4.json",
        "baseStatementSha256": hashlib.sha256(BASELINE.read_bytes()).hexdigest(),
        "codeSha256": DIGEST,
        "vectors": rows,
    }
    (HERE / "MANIFEST.json").write_text(json.dumps(manifest, indent=2) + "\n")


if __name__ == "__main__":
    main()
