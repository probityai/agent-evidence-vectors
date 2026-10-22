"""Generate signed synthetic cases for the optional observed-effect call binding.

The released corpus is an immutable source, never an output. These cases use
its published observer test key and baseline, and the pinned MCP request of the
invocation_axes corpus. They establish verifier behavior, not dispatch, capture
authenticity, or a decision record's correctness.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT / "packaging"))

from agent_evidence_vectors.invocation_axes.reader import (  # noqa: E402
    invocation_binding,
    parse_strict,
)

BASELINE = ROOT / "vectors-observed-effect/statements/v1c6fdd82db5229e4.json"
INVOCATION = ROOT / "packaging/agent_evidence_vectors/invocation_axes/corpus/invocation.json"
SEED = bytes.fromhex("00" * 31 + "11")
KEY = Ed25519PrivateKey.from_private_bytes(SEED)
REQUEST = parse_strict(INVOCATION.read_bytes())
TAGGED = invocation_binding(REQUEST)
assert TAGGED.startswith("sha256:")
BINDING = TAGGED.removeprefix("sha256:")
ABSENT = object()


def request_variant(change: str) -> dict[str, Any]:
    """Return the pinned request with one named change applied."""
    request = copy.deepcopy(REQUEST)
    if change == "id":
        request["id"] = 913
    elif change == "reorder":
        arguments = request["params"]["arguments"]
        request["params"]["arguments"] = dict(reversed(list(arguments.items())))
    elif change == "value":
        request["params"]["arguments"]["status"] = "deleted"
    return request


def bare(request: dict[str, Any]) -> str:
    """Binding of a request as bare 64-hex, the spelling the predicate carries."""
    return invocation_binding(request).removeprefix("sha256:")


def signed(statement: dict[str, Any]) -> dict[str, Any]:
    """Sign deterministic fixture bytes using the public corpus test key."""
    payload_type = "application/vnd.in-toto+json"
    payload = json.dumps(statement, sort_keys=True, separators=(",", ":")).encode()
    pae = b"DSSEv1 %d %s %d %s" % (len(payload_type), payload_type.encode(), len(payload), payload)
    template = json.loads(BASELINE.read_text())
    template["payload"] = base64.b64encode(payload).decode()
    template["signatures"][0]["sig"] = base64.b64encode(KEY.sign(pae)).decode()
    return template


def definitions() -> list[tuple[str, Any, str, str, list[str]]]:
    """Declare each mutation separately from the reader that will judge it."""
    shape = ["invocation-binding-shape"]
    value = ["invocation-binding-value"]
    return [
        ("legacy-absent", ABSENT, "", "valid", []),
        ("present-unrequested", {"sha256": BINDING}, "", "valid", []),
        ("required-match", {"sha256": BINDING}, BINDING, "valid", []),
        ("request-id-differs-match", {"sha256": BINDING}, bare(request_variant("id")), "valid", []),
        (
            "params-member-reordered-match",
            {"sha256": BINDING},
            bare(request_variant("reorder")),
            "valid",
            [],
        ),
        (
            "params-value-changed-mismatch",
            {"sha256": BINDING},
            bare(request_variant("value")),
            "invalid",
            ["invocation-binding-mismatch"],
        ),
        ("required-absent", ABSENT, BINDING, "invalid", ["invocation-binding-required"]),
        (
            "required-mismatch",
            {"sha256": "0" * 64},
            BINDING,
            "invalid",
            ["invocation-binding-mismatch"],
        ),
        ("null-field", None, "", "malformed", shape),
        ("string-field", BINDING, "", "malformed", shape),
        ("array-field", [], "", "malformed", shape),
        ("empty-field", {}, "", "malformed", shape),
        ("unknown-algorithm", {"sha1": "0" * 40}, "", "malformed", shape),
        ("extra-algorithm", {"sha256": BINDING, "sha1": "0" * 40}, "", "malformed", shape),
        ("tagged-value", {"sha256": TAGGED}, "", "malformed", value),
        ("uppercase-value", {"sha256": BINDING.upper()}, "", "malformed", value),
        ("trailing-newline", {"sha256": BINDING + "\n"}, "", "malformed", value),
        ("short-value", {"sha256": BINDING[:-1]}, "", "malformed", value),
        ("nonhex-value", {"sha256": "g" * 64}, "", "malformed", value),
        ("numeric-value", {"sha256": 23}, "", "malformed", value),
        ("null-value", {"sha256": None}, "", "malformed", value),
        (
            "invalid-consumer-pin",
            {"sha256": BINDING},
            "BAD",
            "invalid",
            ["invocation-binding-policy-invalid"],
        ),
    ]


def make_case(
    case_id: str, value: Any, expected_pin: str, verdict: str, codes: list[str]
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Build a signed statement and a separate expected-result manifest row."""
    baseline = json.loads(BASELINE.read_text())
    statement = json.loads(base64.b64decode(baseline["payload"]))
    if value is not ABSENT:
        statement["predicate"]["invocationBinding"] = value
    row = {
        "id": case_id,
        "file": f"fixtures/{case_id}.json",
        "expectedInvocationBinding": expected_pin,
        "expected": {"verdict": verdict, "codes": codes},
    }
    return row, signed(statement)


def extra_cases() -> list[tuple[dict[str, Any], dict[str, Any]]]:
    """Keep subject integrity and signed-payload integrity distinct from joining."""
    row, envelope = make_case("required-match", {"sha256": BINDING}, BINDING, "valid", [])
    statement = json.loads(base64.b64decode(envelope["payload"]))
    outputs = []
    for name, subjects, code in [
        (
            "binding-replaces-after-root",
            [{"name": "call", "digest": {"sha256": BINDING}}],
            "subject-not-the-after-root",
        ),
        (
            "binding-is-second-subject",
            statement["subject"] + [{"name": "call", "digest": {"sha256": BINDING}}],
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
    statement["predicate"]["invocationBinding"]["sha256"] = "0" * 64
    envelope["payload"] = base64.b64encode(
        json.dumps(statement, sort_keys=True, separators=(",", ":")).encode()
    ).decode()
    outputs.append(
        (
            {
                **row,
                "id": "unsigned-binding-change",
                "file": "fixtures/unsigned-binding-change.json",
                "expectedInvocationBinding": "",
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
    manifest = {
        "profile": "observed-invocation-binding-candidate-v1",
        "status": "candidate",
        "classification": "same-author synthetic conformance cases; published test keys",
        "baseStatement": "vectors-observed-effect/statements/v1c6fdd82db5229e4.json",
        "baseStatementSha256": hashlib.sha256(BASELINE.read_bytes()).hexdigest(),
        "request": "packaging/agent_evidence_vectors/invocation_axes/corpus/invocation.json",
        "requestSha256": hashlib.sha256(INVOCATION.read_bytes()).hexdigest(),
        "invocationBinding": BINDING,
        "vectors": rows,
    }
    (HERE / "MANIFEST.json").write_text(json.dumps(manifest, indent=2) + "\n")


if __name__ == "__main__":
    main()
