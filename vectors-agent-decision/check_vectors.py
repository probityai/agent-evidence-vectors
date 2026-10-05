#!/usr/bin/env python3
"""Does the committed corpus behave as MANIFEST.json claims, and is every rule
of the reference reader load-bearing?

    uv run --extra generators python vectors-agent-decision/check_vectors.py

This file is the Python rail's reader for the corpus; `corpora/agentdecision.go`
is the Go rail's, written to the same README rules, and the two must agree on
every member. Three checks, each able to fail on its own:

1. Every member reaches its declared verdict and first refusal code, every
   reject names an accept parent, every admissible argument file canonicalizes
   to the manifest's canonicalArguments, and the corpus digest holds.
2. A second canonicalization path: the canonical bytes of every admissible
   argument file are recomputed with `json` and the repository's own
   `tools/artifact-binding/jcs.py` number writer, so this directory's
   canonicalizer is never the only one grading itself.
3. The rule sweep: disabling any one rule must turn at least one reject member
   into a non-refusal, and must never refuse an accept member. A disabled
   admission rule is replaced by the common library behaviour, so the sweep
   measures whether the corpus catches that library.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import importlib.util
import json
import os
import re
import sys
from dataclasses import dataclass, field
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, HERE)

from canonical import (  # noqa: E402
    ADMISSION_RULES,
    ArgumentsRefused,
    admit_arguments,
    canonical_bytes,
)
from digest import corpus_digest  # noqa: E402

STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
STATES = ("recorded", "redacted", "unavailable", "not_recorded")
HASHED_STATES = ("recorded", "redacted")
DECISIONS = ("allow", "deny")
HASH_PATTERN = re.compile(r"\Asha256:[0-9a-f]{64}\Z")
RFC3339 = re.compile(r"\A\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})\Z")
RULES = (
    "signature",
    "statement",
    "predicate-shape",
    "args-state",
    "args-hash-presence",
    "args-hash-format",
    *ADMISSION_RULES,
    "args-hash-match",
)


@dataclass
class Report:
    verdict: str = "valid"
    codes: list[str] = field(default_factory=list)


class Refused(Exception):
    def __init__(self, verdict: str, code: str) -> None:
        super().__init__(code)
        self.verdict = verdict
        self.code = code


def pae(payload_type: str, payload: bytes) -> bytes:
    kind = payload_type.encode()
    return b"DSSEv1 %d %s %d %s" % (len(kind), kind, len(payload), payload)


def _signature(envelope: dict[str, Any], public_hex: str, payload_type: str) -> bytes:
    """The payload bytes, once the one signature has verified over PAE."""
    if envelope.get("payloadType") != payload_type:
        raise Refused("invalid", "signature-invalid")
    try:
        payload = base64.b64decode(envelope["payload"], validate=True)
        signatures = envelope["signatures"]
        if not isinstance(signatures, list) or len(signatures) != 1:
            raise Refused("invalid", "signature-invalid")
        sig = base64.b64decode(signatures[0]["sig"], validate=True)
        key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_hex))
        key.verify(sig, pae(payload_type, payload))
    except (KeyError, TypeError, binascii.Error, InvalidSignature) as exc:
        raise Refused("invalid", "signature-invalid") from exc
    return payload


def _statement(payload: bytes, predicate_type: str) -> dict[str, Any]:
    try:
        stmt = json.loads(payload)
    except ValueError as exc:
        raise Refused("malformed", "statement-malformed") from exc
    if not isinstance(stmt, dict):
        raise Refused("malformed", "statement-malformed")
    subject = stmt.get("subject")
    subject_ok = (
        isinstance(subject, list)
        and bool(subject)
        and all(
            isinstance(s, dict)
            and isinstance(s.get("name"), str)
            and isinstance(s.get("digest"), dict)
            and bool(s["digest"])
            for s in subject
        )
    )
    if (
        stmt.get("_type") != STATEMENT_TYPE
        or stmt.get("predicateType") != predicate_type
        or not subject_ok
    ):
        raise Refused("malformed", "statement-malformed")
    return stmt


def _is_text(value: Any) -> bool:
    return isinstance(value, str) and value != ""


def _evaluations_ok(evaluations: Any) -> bool:
    if not isinstance(evaluations, list) or not evaluations:
        return False
    return all(
        isinstance(ev, dict)
        and _is_text(ev.get("policy"))
        and ev.get("decision") in DECISIONS
        and isinstance(ev.get("reason"), str)
        for ev in evaluations
    )


def _shape(predicate: Any) -> list[dict[str, Any]]:
    """The RFC's required fields with their types; returns the tool calls."""
    if not isinstance(predicate, dict):
        raise Refused("malformed", "predicate-malformed")
    principal = predicate.get("principal")
    calls = predicate.get("tool_calls")
    decided_at = predicate.get("decided_at")
    ok = (
        _is_text(predicate.get("agent_id"))
        and isinstance(principal, dict)
        and _is_text(principal.get("subject"))
        and _evaluations_ok(predicate.get("policy_evaluations"))
        and isinstance(calls, list)
        and bool(calls)
        and all(isinstance(c, dict) and _is_text(c.get("name")) for c in calls)
        and isinstance(decided_at, str)
        and bool(RFC3339.match(decided_at))
    )
    if not ok or not isinstance(calls, list):
        raise Refused("malformed", "predicate-malformed")
    return calls


def _declarations(call: dict[str, Any], disabled: str) -> None:
    """args_state, then args_hash presence, then its format."""
    state = call.get("args_state")
    if disabled != "args-state":
        if "args_state" not in call:
            raise Refused("malformed", "args-state-missing")
        if state not in STATES:
            raise Refused("malformed", "args-state-unknown")
    present = "args_hash" in call
    if disabled != "args-hash-presence":
        if state in HASHED_STATES and not present:
            raise Refused("malformed", "args-hash-required")
        if state in STATES and state not in HASHED_STATES and present:
            raise Refused("malformed", "args-hash-forbidden")
    digest = call.get("args_hash")
    well_formed = isinstance(digest, str) and HASH_PATTERN.match(digest)
    if present and disabled != "args-hash-format" and not well_formed:
        raise Refused("malformed", "args-hash-format")


def _call(call: dict[str, Any], arguments: bytes | None, disabled: str) -> None:
    _declarations(call, disabled)
    digest = call.get("args_hash")
    if call.get("args_state") != "recorded" or arguments is None or not isinstance(digest, str):
        return
    lenient = frozenset({disabled}) & frozenset(ADMISSION_RULES)
    try:
        value = admit_arguments(arguments, lenient)
    except ArgumentsRefused as exc:
        raise Refused("malformed", exc.code) from exc
    computed = "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()
    if disabled != "args-hash-match" and computed != digest.lower():
        raise Refused("invalid", "args-hash-mismatch")


def verify(
    envelope_bytes: bytes,
    arguments: bytes | None,
    manifest: dict[str, Any],
    disabled: str = "",
) -> Report:
    """Judge one member: an envelope, and the arguments it discloses if any."""
    try:
        envelope = json.loads(envelope_bytes)
        if not isinstance(envelope, dict):
            raise Refused("invalid", "signature-invalid")
        if disabled == "signature":
            payload = base64.b64decode(envelope["payload"])
        else:
            payload = _signature(
                envelope, manifest["keys"]["producer"]["publicKey"], manifest["payloadType"]
            )
        if disabled == "statement":
            stmt = json.loads(payload)
        else:
            stmt = _statement(payload, manifest["predicateType"])
        predicate = stmt.get("predicate")
        if disabled == "predicate-shape":
            calls = predicate.get("tool_calls") or [] if isinstance(predicate, dict) else []
        else:
            calls = _shape(predicate)
        for call in calls:
            _call(call, arguments, disabled)
    except Refused as refused:
        return Report(refused.verdict, [refused.code])
    except (ValueError, KeyError, TypeError, AttributeError):
        return Report("malformed", ["statement-malformed"])
    return Report()


def _read(rel: str) -> bytes:
    with open(os.path.join(HERE, rel), "rb") as fh:
        return fh.read()


def _arguments(entry: dict[str, Any]) -> bytes | None:
    return _read(entry["arguments"]) if "arguments" in entry else None


def judge(manifest: dict[str, Any]) -> list[str]:
    findings: list[str] = []
    entries = manifest["vectors"]
    accepts = {e["id"] for e in entries if e["kind"] == "accept"}
    counts = {"accept": 0, "reject": 0}
    for entry in entries:
        counts[entry["kind"]] += 1
        report = verify(_read(entry["file"]), _arguments(entry), manifest)
        expected = entry["expected"]
        if report.verdict != expected["verdict"] or report.codes != expected["codes"]:
            findings.append(
                f"{entry['id']} ({entry['slug']}): "
                f"expected {expected['verdict']} {expected['codes']}, "
                f"reached {report.verdict} {report.codes}"
            )
        if entry["kind"] == "reject" and entry.get("parent") not in accepts:
            findings.append(f"{entry['id']} ({entry['slug']}): parent is not an accept member")
        if "canonicalArguments" in entry:
            got = canonical_bytes(admit_arguments(_read(entry["arguments"]))).decode()
            if got != entry["canonicalArguments"]:
                findings.append(f"{entry['id']} ({entry['slug']}): canonicalArguments disagrees")
    if counts != manifest["counts"]:
        findings.append(f"counts {manifest['counts']} disagree with the members {counts}")
    if corpus_digest(manifest, HERE) != manifest["corpusDigest"]:
        findings.append("corpusDigest does not match the committed bytes")
    return findings


def _second_path(manifest: dict[str, Any]) -> list[str]:
    """Recompute canonicalArguments with the artifact-binding number writer."""
    path = os.path.join(REPO, "tools", "artifact-binding", "jcs.py")
    spec = importlib.util.spec_from_file_location("artifact_binding_jcs", path)
    if spec is None or spec.loader is None:
        return [f"{path} cannot be loaded, so the second canonicalization path did not run"]
    other = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(other)

    def encode(node: Any) -> str:
        if isinstance(node, bool) or node is None or isinstance(node, str):
            return json.dumps(node, ensure_ascii=False)
        if isinstance(node, (int, float)):
            return str(other.es6_number(float(node)))
        if isinstance(node, dict):
            items = sorted(node.items(), key=lambda kv: kv[0].encode("utf-16-be"))
            return "{" + ",".join(f"{encode(k)}:{encode(v)}" for k, v in items) + "}"
        return "[" + ",".join(encode(v) for v in node) + "]"

    findings = []
    for entry in manifest["vectors"]:
        if "canonicalArguments" not in entry:
            continue
        text = encode(json.loads(_read(entry["arguments"])))
        if text != entry["canonicalArguments"]:
            findings.append(f"{entry['slug']}: a second canonicalizer writes {text}")
    return findings


def sweep(manifest: dict[str, Any]) -> list[str]:
    findings: list[str] = []
    bodies = [(e, _read(e["file"]), _arguments(e)) for e in manifest["vectors"]]
    for rule in RULES:
        flipped = []
        for entry, body, arguments in bodies:
            report = verify(body, arguments, manifest, disabled=rule)
            if entry["kind"] == "accept" and report.verdict != "valid":
                findings.append(f"disabling {rule} refuses accept member {entry['slug']}")
            if entry["kind"] == "reject" and report.verdict == "valid":
                flipped.append(entry["slug"])
        if not flipped:
            findings.append(f"rule {rule} is inert: disabling it admits no reject member")
        else:
            print(f"rule {rule}: disabling it admits {', '.join(flipped)}")
    return findings


def main() -> int:
    with open(os.path.join(HERE, "MANIFEST.json"), encoding="utf-8") as fh:
        manifest = json.load(fh)
    findings = judge(manifest) + _second_path(manifest) + sweep(manifest)
    for finding in findings:
        print(f"FAIL check: {finding}")
    if findings:
        return 1
    print(
        f"check: {manifest['counts']} members behave as declared, a second canonicalizer "
        "agrees, and every rule is load-bearing"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
