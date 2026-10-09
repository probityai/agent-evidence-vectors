"""Judge the OWASP MCP verification corpus (vectors-mcp-owasp/).

Each member is the observation one acceptance test of a draft MCP verification
requirement (MCPVS-1 to MCPVS-12) produced. The requirement it tests selects a
rule below, and the rule decides whether the observed behaviour passes that
acceptance test. Every requirement carries one member that must be accepted and
one that must be rejected, and the rejected member differs from its accepting
twin in exactly one observation field, so a reader that refuses everything
scores zero rather than full marks.

The threat identifiers (MCPTM-1 to MCPTM-10) are tested through the
requirements their registry row names, so every threat row reaches an accept
and a reject member through those requirements.

The rules are restated in Go in corpora/mcpowasp.go. The two are kept apart on
purpose: one rule written once and run by both rails would agree with itself.

Standard library only, so the installed package judges the corpus offline.
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

SUITE = "owasp-mcp-verification-draft"

_HERE = Path(__file__).resolve().parent
ROOT = (
    _HERE / "corpora" / "vectors-mcp-owasp"
    if (_HERE / "corpora").exists()
    else _HERE.parents[1] / "vectors-mcp-owasp"
)

_ID = re.compile(r"^(MCPVS|MCPTM)-([1-9][0-9]*)$")


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def compact(value: Any) -> bytes:
    """The one canonical form this corpus hashes: sorted keys, no spaces."""
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


# ---------------------------------------------------------------------------
# The twelve acceptance tests. Each returns None when the observation passes
# the test and a reason when it does not.
# ---------------------------------------------------------------------------

Rule = Callable[[dict[str, Any]], "str | None"]


def _strs(value: Any) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        return []
    return list(value)


def rule_tool_pin(o: dict[str, Any]) -> str | None:
    approved, served = o.get("approvedDigest"), o.get("servedDigest")
    if not approved or approved == served:
        return (
            "the served definition does not differ from the approved one, so the test was not run"
        )
    if o.get("clientDecision") != "refused":
        return "the client accepted a tool whose definition digest differs from the approved one"
    reported = _strs(o.get("reportedDigests"))
    if approved not in reported or served not in reported:
        return "the refusal does not report both digests"
    return None


def rule_pin_survives_restart(o: dict[str, Any]) -> str | None:
    approved, served = o.get("approvedDigest"), o.get("servedDigest")
    if not approved or approved == served:
        return (
            "the served definition does not differ from the approved one, so the test was not run"
        )
    connections = o.get("connections")
    if not isinstance(connections, list) or not connections:
        return "no connection was observed"
    if not any(isinstance(c, dict) and c.get("afterRestart") is True for c in connections):
        return "no connection after a restart was observed, so the test was not run"
    for index, c in enumerate(connections):
        if not isinstance(c, dict) or c.get("decision") != "refused":
            return f"connection {index + 1} accepted the altered definition"
    return None


def _flatten_strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [s for v in value.values() for s in _flatten_strings(v)]
    if isinstance(value, list):
        return [s for v in value for s in _flatten_strings(v)]
    return []


def rule_credential_isolation(o: dict[str, Any]) -> str | None:
    tokens = o.get("tokens")
    called = o.get("calledServer")
    if not isinstance(tokens, dict) or len(tokens) < 2 or called not in tokens:
        return "fewer than two servers with distinct tokens, so the test was not run"
    headers = _flatten_strings(o.get("receivedHeaders"))
    arguments = _flatten_strings(o.get("receivedArguments"))
    for server, token in sorted(tokens.items()):
        if server != called and any(token in h for h in headers):
            return f"the token issued for server {server} reached server {called} in a header"
        if any(token in a for a in arguments):
            return f"the token issued for server {server} was placed in a tool argument"
    return None


def rule_session_scope(o: dict[str, Any]) -> str | None:
    session = _strs(o.get("sessionScopes"))
    required = o.get("callRequires")
    if not isinstance(required, str) or required in session:
        return "the call does not require a scope outside the session, so the test was not run"
    if required not in _strs(o.get("grantedAcrossSessions")):
        return "the required scope was never granted in any session, so the test was not run"
    if o.get("decision") != "refused":
        return "a call was authorized against a scope granted in another session"
    return None


_INJECTIONS = ("; id", "$(id)", "`id`")


def rule_no_shell_interpolation(o: dict[str, Any]) -> str | None:
    sent = _strs(o.get("payloads"))
    if any(p not in sent for p in _INJECTIONS):
        return "not every injection token was sent, so the test was not run"
    for where in ("spawnedProcesses", "auditRecordProcesses"):
        processes = o.get(where)
        if not isinstance(processes, list):
            return f"{where} was not observed"
        for argv in processes:
            if isinstance(argv, list) and argv and argv[0] == "id":
                return f"the injected command ran, as observed in {where}"
    return None


def rule_content_is_data(o: dict[str, Any]) -> str | None:
    before, after = o.get("before"), o.get("after")
    if not isinstance(before, dict) or not isinstance(after, dict):
        return "the state before and after was not observed"
    for key in ("tools", "scopes", "approval"):
        if before.get(key) != after.get(key):
            return f"returned content changed the {key}"
    if o.get("unapprovedCallsAfter") != 0:
        return "a tool call followed the returned content without a fresh approval"
    if o.get("contentRecordedAs") != "data":
        return "the returned content was not recorded as data"
    return None


def rule_server_identity(o: dict[str, Any]) -> str | None:
    configured = _strs(o.get("configuredDigests"))
    launched = o.get("launchedDigest")
    if not configured or launched in configured:
        return "the launched artifact is in the configured set, so the test was not run"
    if o.get("decision") != "refused":
        return "the client started a server whose artifact digest is absent from the configured set"
    if o.get("namedExpected") not in configured:
        return "the refusal does not name the digest the client expected"
    return None


_RECORD_FIELDS = (
    "server",
    "toolDigest",
    "principal",
    "approvalState",
    "argumentsDigest",
    "outcome",
)


def rule_call_record(o: dict[str, Any]) -> str | None:
    records = o.get("records")
    if not isinstance(records, list) or len(records) != 2:
        return "the test needs one approved call and one call with no approval decision"
    for index, record in enumerate(records):
        if not isinstance(record, dict):
            return f"record {index + 1} is not an object"
        for name in _RECORD_FIELDS:
            if not record.get(name):
                return f"record {index + 1} does not carry {name}"
    if records[0]["approvalState"] == records[1]["approvalState"]:
        return "a call with no approval decision is recorded the same as an approved one"
    return None


def chain_break(stream: list[Any]) -> int | None:
    """The sequence number of the first record whose predecessor link fails."""
    previous: Any = None
    for record in stream:
        if not isinstance(record, dict):
            return -1
        expected = "" if previous is None else sha(compact(previous))
        if record.get("prev") != expected:
            seq = record.get("seq")
            return seq if isinstance(seq, int) else -1
        previous = record
    return None


def rule_tamper_evident(o: dict[str, Any]) -> str | None:
    stream = o.get("stream")
    if not isinstance(stream, list) or not stream:
        return "no record stream was observed"
    broken = chain_break(stream)
    if broken is None:
        return "the stream is intact, so the deletion test was not run"
    if o.get("headHolder") in (None, "", "client"):
        return "the head is held by the client alone"
    verification = o.get("verification")
    if not isinstance(verification, dict) or verification.get("result") != "fail":
        return "verification passed a stream with a record deleted"
    if verification.get("breakAt") != broken:
        return "verification failed without naming the break"
    resigned = o.get("verificationAfterResign")
    if not isinstance(resigned, dict) or resigned.get("result") != "fail":
        return (
            "verification against the published head passed after the client "
            "re-signed the stream alone"
        )
    return None


def rule_untrusted_workspace(o: dict[str, Any]) -> str | None:
    untrusted = _strs(o.get("untrustedConfigServers"))
    started = _strs(o.get("started"))
    if not untrusted:
        return "the workspace carried no server configuration, so the test was not run"
    if any(name in started for name in untrusted):
        return "a server from an untrusted workspace configuration started"
    if o.get("refusalReported") is not True:
        return "the refusal was not reported"
    if sorted(_strs(o.get("reportedStarted"))) != sorted(started):
        return "the report does not list the servers that did start"
    return None


def rule_end_user_attribution(o: dict[str, Any]) -> str | None:
    calls = o.get("calls")
    if not isinstance(calls, list) or not any(
        isinstance(c, dict) and c.get("userBound") is False for c in calls
    ):
        return "no call without a bound user was sent, so the test was not run"
    for index, call in enumerate(calls):
        if not isinstance(call, dict):
            return f"call {index + 1} is not an object"
        if call.get("userBound") is True and call.get("decision") != "accepted":
            return f"call {index + 1} carried a bound user and was refused"
        if call.get("userBound") is False:
            if call.get("decision") != "refused":
                return f"call {index + 1} could not be attributed to a user and was accepted"
            if not call.get("recordedReason"):
                return f"call {index + 1} was refused and no reason was recorded"
    return None


def rule_declared_arguments_only(o: dict[str, Any]) -> str | None:
    declared = _strs(o.get("declaredParameters"))
    held = _strs(o.get("sessionHeld"))
    if not declared or not held:
        return "the session held nothing beyond the declared parameters, so the test was not run"
    extra = [k for k in _strs(o.get("requestLogKeys")) if k not in declared]
    if extra:
        return f"the request carried fields the schema does not declare: {extra}"
    return None


RULES: dict[str, Rule] = {
    "MCPVS-1": rule_tool_pin,
    "MCPVS-2": rule_pin_survives_restart,
    "MCPVS-3": rule_credential_isolation,
    "MCPVS-4": rule_session_scope,
    "MCPVS-5": rule_no_shell_interpolation,
    "MCPVS-6": rule_content_is_data,
    "MCPVS-7": rule_server_identity,
    "MCPVS-8": rule_call_record,
    "MCPVS-9": rule_tamper_evident,
    "MCPVS-10": rule_untrusted_workspace,
    "MCPVS-11": rule_end_user_attribution,
    "MCPVS-12": rule_declared_arguments_only,
}


def verdict(record: dict[str, Any]) -> tuple[str, str | None]:
    """Accept or reject one member record, with the reason for a reject."""
    rule = RULES.get(str(record.get("requirement")))
    observation = record.get("observation")
    if rule is None:
        return "reject", f"no rule for requirement {record.get('requirement')!r}"
    if not isinstance(observation, dict):
        return "reject", "the record carries no observation"
    reason = rule(observation)
    return ("accept", None) if reason is None else ("reject", reason)


def identify(kind: str, conditions: list[str], payload: Any) -> str:
    return "v" + sha(compact({"kind": kind, "conditions": conditions, "payload": payload}))[:16]


# ---------------------------------------------------------------------------
# Judging the directory.
# ---------------------------------------------------------------------------


@dataclass
class Member:
    id: str
    kind: str
    findings: list[str] = field(default_factory=list)


@dataclass
class Judged:
    members: list[Member] = field(default_factory=list)
    findings: list[str] = field(default_factory=list)

    def ok(self) -> bool:
        return not self.findings and all(not m.findings for m in self.members)


def _ordered(ids: list[str]) -> list[str]:
    def key(identifier: str) -> tuple[str, int]:
        match = _ID.match(identifier)
        return (match.group(1), int(match.group(2))) if match else ("", 0)

    return sorted(ids, key=key)


def _check_registry(
    registry: dict[str, Any], judged: Judged
) -> tuple[set[str], dict[str, list[str]]]:
    requirements = {r["id"] for r in registry.get("requirements", []) if isinstance(r, dict)}
    threats = {
        t["id"]: _strs(t.get("testedBy"))
        for t in registry.get("threats", [])
        if isinstance(t, dict)
    }
    for prefix, ids in (("MCPVS", sorted(requirements)), ("MCPTM", sorted(threats))):
        numbers = sorted(
            int(m.group(2)) for i in ids if (m := _ID.match(i)) and m.group(1) == prefix
        )
        if numbers != list(range(1, len(ids) + 1)):
            judged.findings.append(
                f"{prefix} identifiers are not minted as 1..{len(ids)}: {_ordered(ids)}"
            )
    for threat, tested_by in sorted(threats.items()):
        if not tested_by:
            judged.findings.append(f"{threat} names no requirement that tests it")
        for requirement in tested_by:
            if requirement not in requirements:
                judged.findings.append(
                    f"{threat} is tested by {requirement}, which the registry does not mint"
                )
    if set(RULES) != requirements:
        judged.findings.append("the registry and this reader's rules name different requirements")
    return requirements, threats


def _judge_member(root: Path, entry: dict[str, Any], member: Member) -> tuple[bytes, Any]:
    """Judge one member's own bytes; return them and the parsed record."""
    path = root / entry["record"]
    if not path.is_file():
        member.findings.append("the manifest names a record file that does not exist")
        return b"", None
    raw = path.read_bytes()
    record = json.loads(raw)
    conditions = entry.get("conditions", [])
    if conditions != [record.get("requirement")]:
        member.findings.append("cites a condition other than the requirement its record tests")
    if identify(entry["kind"], conditions, record) != entry["id"]:
        member.findings.append("identifier does not recompute from the member's own bytes")
    got, reason = verdict(record)
    if got != entry["kind"]:
        member.findings.append(f"declares {entry['kind']} and the rule answers {got}: {reason}")
    return raw, record


def _check_twins(
    manifest: dict[str, Any], records: dict[str, dict[str, Any]], judged: Judged
) -> None:
    """A reject member differs from its accepting twin in exactly one field."""
    for entry in manifest["vectors"]:
        if entry["kind"] != "reject":
            continue
        twin = records.get(entry.get("twin", ""))
        mine = records.get(entry["id"])
        if twin is None or mine is None:
            _member(judged, entry["id"]).findings.append("names no accepting twin")
            continue
        a, b = twin.get("observation", {}), mine.get("observation", {})
        differing = sorted(k for k in set(a) | set(b) if a.get(k) != b.get(k))
        if len(differing) != 1 or twin.get("requirement") != mine.get("requirement"):
            _member(judged, entry["id"]).findings.append(
                f"differs from its accepting twin in {differing}, not in exactly one field"
            )


def _check_coverage(
    kinds: dict[str, set[str]], threats: dict[str, list[str]], judged: Judged
) -> None:
    """Every requirement, and every threat through them, reaches both kinds."""
    for requirement, seen in sorted(kinds.items()):
        if seen != {"accept", "reject"}:
            judged.findings.append(
                f"{requirement} carries {sorted(seen)} members, not one accept and one reject"
            )
    for threat, tested_by in sorted(threats.items()):
        reached = set().union(*(kinds.get(r, set()) for r in tested_by)) if tested_by else set()
        if reached != {"accept", "reject"}:
            judged.findings.append(
                f"{threat} reaches {sorted(reached)} members through {tested_by}"
            )


def judge(directory: str | Path = ROOT) -> Judged:
    root = Path(directory)
    judged = Judged()
    manifest = json.loads((root / "MANIFEST.json").read_text(encoding="utf-8"))
    registry = json.loads((root / manifest["registry"]).read_text(encoding="utf-8"))
    requirements, threats = _check_registry(registry, judged)
    if manifest.get("suite") != SUITE:
        judged.findings.append(f"suite is {manifest.get('suite')!r}, not {SUITE!r}")
    records: dict[str, dict[str, Any]] = {}
    kinds: dict[str, set[str]] = {r: set() for r in requirements}
    body = b""
    for entry in sorted(manifest["vectors"], key=lambda e: e["id"]):
        member = Member(entry["id"], entry["kind"])
        judged.members.append(member)
        raw, record = _judge_member(root, entry, member)
        body += raw
        if record is None:
            continue
        records[entry["id"]] = record
        kinds.get(record.get("requirement"), set()).add(entry["kind"])
    _check_twins(manifest, records, judged)
    _check_coverage(kinds, threats, judged)
    counts = {
        k: sum(1 for e in manifest["vectors"] if e["kind"] == k) for k in ("accept", "reject")
    }
    if counts != manifest.get("counts"):
        judged.findings.append(
            f"counts declare {manifest.get('counts')} and the tree holds {counts}"
        )
    if sha(body) != manifest.get("corpusDigest"):
        judged.findings.append("corpusDigest does not match the record files on disk")
    return judged


def _member(judged: Judged, identifier: str) -> Member:
    return next(m for m in judged.members if m.id == identifier)


def render(judged: Judged, suite: str = SUITE) -> str:
    lines = [f"suite {suite}"]
    for member in judged.members:
        status = "ok" if not member.findings else "FAIL"
        lines.append(f"{status} {member.id} {member.kind}")
        lines.extend(f"  - {finding}" for finding in member.findings)
    lines.extend(f"FAIL corpus: {finding}" for finding in judged.findings)
    accept = sum(1 for m in judged.members if m.kind == "accept")
    reject = sum(1 for m in judged.members if m.kind == "reject")
    lines.append(f"{'ok' if judged.ok() else 'FAIL'}: {accept} accept, {reject} reject")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    judged = judge(args[0] if args else ROOT)
    sys.stdout.write(render(judged))
    return 0 if judged.ok() else 1


if __name__ == "__main__":
    raise SystemExit(main())
