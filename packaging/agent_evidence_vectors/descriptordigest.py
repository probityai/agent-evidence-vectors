"""Judge one pin against one observation of an MCP tool descriptor, digest by digest.

A tool-descriptor digest is a bare ``sha256`` string until a profile says which
bytes it covers. Public digests disagree on the field set (name, description,
inputSchema and outputSchema, or also title and annotations), on an absent
member (an empty description or an omitted one) and on what the member is
canonicalized as. Two honest implementations can therefore produce different
digests for a descriptor that never changed, and a pin and an observation
produced by different code can then read as ``contradicted``, the strongest
negative verdict, over bytes nobody compared. The OWASP Agentic-Evidence
project's rule for this (issue 4) is that a pin and an observation compare only
when both carry a profile and the two profiles are equal; where they differ the
result is a gap, not a contradiction.

Every record is one pin and one observation, each a ``profile``, a ``digest`` and
the ``descriptor`` the digest was computed from. The three closed profiles are
named by what they cover:

- ``name-description-inputschema.omit-absent.jcs``: the members name,
  description and inputSchema; an absent member is omitted;
- ``name-description-inputschema-outputschema.empty-description.jcs``: the same
  plus outputSchema; an absent or non-string description is the empty string and
  any other absent member is omitted (the title, annotations and _meta members
  are not covered);
- ``whole-descriptor.omit-absent.jcs``: every member except ``_meta``, absent
  members omitted.

A digest is ``sha256-`` and the base64 of the SHA-256 of the RFC 8785 bytes of
the covered projection. This suite admits integers, strings, booleans, null,
arrays and objects; a descriptor carrying a non-integer number has no digest here
(``descriptor_not_canonicalizable``).

The reader checks in a fixed order and names the first check that fails:

1. the record carries ``contractId`` (``contract_id_missing``);
2. ``contractId`` is the descriptor-digest contract (``contract_id_unknown``);
3. a profile that is present is one of the three (``profile_unknown``);
4. each descriptor under a present profile has an RFC 8785 form
   (``descriptor_not_canonicalizable``);
5. each stated digest equals the one recomputed from its descriptor under its own
   profile (``digest_not_recomputed``).

A record that passes is then compared: a missing profile on either side is a
``gap`` (``profile_absent``); two profiles that differ are a ``gap``
(``profiles_differ``) even when the digests happen to be equal; two equal
profiles with different digests are ``contradicted`` (``descriptor_changed``);
two equal profiles with equal digests are a ``match`` (``descriptor_unchanged``).

The external-verifier contract: ``<verifier> <case-dir>/record.json --json``
prints one JSON object carrying ``decision`` and ``reason`` and exits 0 for
``match``, 1 for ``contradicted``, 2 for ``gap`` and 3 for ``refused``.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import shlex
import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import Any

from agent_evidence_vectors.monitorcoverage import (
    _fixture_error,
    _validated_entries,
    run_corpus,
)

from . import strictjson

SUITE = "tool-descriptor-digest/v1"
CONTRACT_ID = (
    "https://probityai.github.io/agent-evidence-vectors/predicate/v1/tool-descriptor-digest"
)
MATCH, CONTRADICTED, GAP, REFUSED = "match", "contradicted", "gap", "refused"
EXIT_FOR = {MATCH: 0, CONTRADICTED: 1, GAP: 2, REFUSED: 3}
NDI = "name-description-inputschema.omit-absent.jcs"
NDIO = "name-description-inputschema-outputschema.empty-description.jcs"
WHOLE = "whole-descriptor.omit-absent.jcs"
PROFILES = (NDI, NDIO, WHOLE)
CHECKS = (
    "contract_id_missing",
    "contract_id_unknown",
    "profile_unknown",
    "descriptor_not_canonicalizable",
    "digest_not_recomputed",
)
GAPS = ("profile_absent", "profiles_differ")
_HERE = Path(__file__).resolve().parent
ROOT = (
    _HERE / "corpora" / "vectors-tool-descriptor-digest"
    if (_HERE / "corpora").exists()
    else _HERE.parents[1] / "corpora" / "vectors-tool-descriptor-digest"
)

Record = dict[str, Any]


class NotCanonicalizable(ValueError):
    """A value the suite has no RFC 8785 form for."""


def _encode(node: Any) -> str:
    if node is None:
        return "null"
    if node is True:
        return "true"
    if node is False:
        return "false"
    if isinstance(node, str):
        return json.dumps(node, ensure_ascii=False, separators=(",", ":"))
    if isinstance(node, int):
        if abs(node) >= 2**53:
            raise NotCanonicalizable("integer outside the I-JSON range")
        return str(node)
    if isinstance(node, list):
        return "[" + ",".join(_encode(item) for item in node) + "]"
    if isinstance(node, dict):
        members = sorted(node.items(), key=lambda pair: pair[0].encode("utf-16-be"))
        return "{" + ",".join(f"{_encode(key)}:{_encode(value)}" for key, value in members) + "}"
    raise NotCanonicalizable(type(node).__name__)


def jcs(node: Any) -> bytes:
    """The RFC 8785 bytes of a value this suite admits."""
    return _encode(node).encode("utf-8")


def project(descriptor: dict[str, Any], profile: str) -> dict[str, Any]:
    """The members a profile covers, with its absent-member rule applied."""
    if profile == WHOLE:
        return {key: value for key, value in descriptor.items() if key != "_meta"}
    covered = ["name", "description", "inputSchema"] + (["outputSchema"] if profile == NDIO else [])
    covered_members = {key: descriptor[key] for key in covered if key in descriptor}
    if profile == NDIO and not isinstance(covered_members.get("description"), str):
        covered_members["description"] = ""
    return covered_members


def digest(descriptor: dict[str, Any], profile: str) -> str:
    """The digest of a descriptor under a profile, as a ``sha256-`` string."""
    raw = hashlib.sha256(jcs(project(descriptor, profile))).digest()
    return "sha256-" + base64.b64encode(raw).decode("ascii")


def _sides(record: Record) -> list[dict[str, Any]]:
    return [record.get("pin") or {}, record.get("observation") or {}]


def retained(record: Record) -> dict[str, str]:
    """The two profiles and whether the stated digests are equal, as a verifier keeps them."""
    pin, observation = _sides(record)
    return {
        "digestsEqual": "true" if pin.get("digest") == observation.get("digest") else "false",
        "observation": str(observation.get("profile", "absent")),
        "pin": str(pin.get("profile", "absent")),
    }


def _unknown_profile(record: Record) -> bool:
    return any("profile" in side and side["profile"] not in PROFILES for side in _sides(record))


def _uncanonicalizable(record: Record) -> bool:
    for side in _sides(record):
        if side.get("profile") not in PROFILES or "descriptor" not in side:
            continue
        try:
            digest(side["descriptor"], side["profile"])
        except NotCanonicalizable:
            return True
    return False


def _recomputed_differs(side: dict[str, Any]) -> bool:
    """True when the side's digest is not what its descriptor gives, or cannot be recomputed."""
    try:
        return digest(side["descriptor"], side["profile"]) != side.get("digest")
    except NotCanonicalizable:
        return True


def _not_recomputed(record: Record) -> bool:
    return any(
        side.get("profile") in PROFILES and "descriptor" in side and _recomputed_differs(side)
        for side in _sides(record)
    )


def _first_failure(record: Record, skip: frozenset[str]) -> str | None:
    """Name the first check in ``CHECKS`` the record fails, or None.

    ``skip`` switches named checks off so the corpus's own tests can prove each
    check is forced by some member; a verifier never sets it.
    """
    failures: dict[str, Callable[[], bool]] = {
        "contract_id_missing": lambda: "contractId" not in record,
        "contract_id_unknown": lambda: record.get("contractId", CONTRACT_ID) != CONTRACT_ID,
        "profile_unknown": lambda: _unknown_profile(record),
        "descriptor_not_canonicalizable": lambda: _uncanonicalizable(record),
        "digest_not_recomputed": lambda: _not_recomputed(record),
    }
    for name in CHECKS:
        if name not in skip and failures[name]():
            return name
    return None


def judge(record: Record, skip: frozenset[str] = frozenset()) -> dict[str, str]:
    """The reference reader's decision and reason for one parsed record."""
    failure = _first_failure(record, skip)
    if failure is not None:
        return {"decision": REFUSED, "reason": failure}
    pin, observation = _sides(record)
    pin_profile, observed_profile = pin.get("profile"), observation.get("profile")
    if pin_profile is None or observed_profile is None:
        return {"decision": GAP, "reason": "profile_absent"}
    if pin_profile != observed_profile:
        return {"decision": GAP, "reason": "profiles_differ"}
    if pin.get("digest") != observation.get("digest"):
        return {"decision": CONTRADICTED, "reason": "descriptor_changed"}
    return {"decision": MATCH, "reason": "descriptor_unchanged"}


def _load(record_path: Path) -> Record:
    loaded: Record = strictjson.loads(record_path.read_text(encoding="utf-8"))
    return loaded


def verify(record_path: Path, skip: frozenset[str] = frozenset()) -> dict[str, str]:
    """The reference reader's decision and reason for one record file."""
    return judge(_load(record_path), skip)


def external_answer(command: list[str], path: Path) -> tuple[bool, dict[str, Any] | str]:
    """Run one external verifier on one record and read its decision."""
    try:
        result = subprocess.run(
            [*command, str(path), "--json"],
            capture_output=True,
            text=True,
            timeout=90,
            check=False,
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


def check(
    verifier: str | list[str] | None = None,
    root: Path = ROOT,
    skip: frozenset[str] = frozenset(),
) -> tuple[int, list[str]]:
    """Check every record, through the named verifier or the reference reader."""
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
        record_path = directory / "record.json"
        if retained(_load(record_path)) != entry["retained"]:
            errors.append(f"{name}: declared retained fields do not hold")
        observed: dict[str, Any] | str
        if command is None:
            ran, observed = True, verify(record_path, skip)
        else:
            ran, observed = external_answer(command, record_path)
        answered += int(ran)
        if isinstance(observed, str):
            errors.append(f"{name}: {observed}")
        elif observed != entry["expected"]:
            errors.append(f"{name}: expected {entry['expected']}, got {observed}")
    return answered, errors


def run(root: str, verifier: list[str] | None, report_path: str, rail_note: str) -> int:
    """Judge the corpus and write the report the package's other suites write."""
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
