"""Build the identity-assurance-levels cases byte-identically.

Every case is one record set: a subject and the findings other suites reached about it. The
evidence of each finding is a member of a sibling corpus, pointed at by digest through
``reuse.json`` (see ``reuse.py``); this generator copies none of their bytes. The cases hold
one set per level, a set that skips each level, and a set for each way a finding or a set
can be refused. The levels and their tests are defined in
``spec/predicates/identity-assurance-levels.md``.
"""

from __future__ import annotations

import copy
import hashlib
import json
import shutil
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parents[1] / "packaging"))
sys.path.insert(0, str(ROOT))

import reuse  # noqa: E402
from agent_evidence_vectors import assurancelevels as reader  # noqa: E402

SUITE = reader.SUITE
SUBJECT = "agent:planner"
SOURCES = {
    "rfc8693": {"title": "RFC 8693", "url": "https://www.rfc-editor.org/rfc/rfc8693"},
    "rfc9449": {"title": "RFC 9449", "url": "https://www.rfc-editor.org/rfc/rfc9449"},
    "rfc7800": {"title": "RFC 7800", "url": "https://www.rfc-editor.org/rfc/rfc7800"},
}

Case = tuple[str, dict[str, Any], str, str, str]


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()


def finding(key: str, *, subject: str = SUBJECT, **override: Any) -> dict[str, Any]:
    """One finding, taken from the reuse pointer ``<corpus>/<member>``."""
    entry = reuse.load()[key]
    item: dict[str, Any] = {
        "decision": entry["decision"],
        "evidence": {
            "corpus": entry["corpus"],
            "file": entry["file"],
            "member": entry["member"],
            "sha256": entry["sha256"],
        },
        "reason": entry["reason"],
        "subject": subject,
        "suite": entry["suite"],
    }
    if "rung" in entry:
        item["rung"] = entry["rung"]
    item.update(override)
    for name in [k for k, v in item.items() if v is None]:
        del item[name]
    return item


def build(*findings: dict[str, Any], subject: str = SUBJECT) -> dict[str, Any]:
    return {"contractId": reader.CONTRACT_ID, "findings": list(findings), "subject": subject}


# The accepted evidence for each test, by pointer.
T1 = "vectors-principal-binding/uma-bound"
T1_DID = "vectors-identity-binding/web-verified"
T2 = "vectors-actor-marker-survival/accept-two-hop"
T3 = "vectors-holder-bound-credential/accept-single-presentation"
T4 = "vectors-delegator-right/allow-entitled-delegator"
T6 = "vectors-grade-floor/e2-enforced"
T5 = "vectors-credential-reachability/contained"
LADDER = [T1, T2, T3, T4, T5, T6]


def ladder(upto: int, skip: tuple[int, ...] = ()) -> list[dict[str, Any]]:
    """Accepted findings for tests T1..T<upto>, leaving out the tests named in skip."""
    return [
        finding(key)
        for index, key in enumerate(LADDER, start=1)
        if index <= upto and index not in skip
    ]


def _evidence_swapped() -> dict[str, Any]:
    """The T3 finding for another subject: a holder-bound credential that is not the agent's."""
    return build(*ladder(2), finding(T3, subject="agent:intruder"))


def _one_evidence_six_suites() -> dict[str, Any]:
    """One digest listed as the proof of every test, which six suites' records cannot share."""
    base = finding(T1)
    proving = [
        ("agent-principal-binding/v1", "agent_bound", None),
        ("actor-marker-survival/v1", "marker_survives", None),
        ("holder-bound-credential/v1", "holder_bound", None),
        ("delegator-right/v1", "entitled", None),
        ("credential-reachability/v1", "contained_verified", None),
        ("evidence-grade-floor/v1", "grade_derived", "E3"),
    ]
    return build(
        *[
            dict(base, suite=suite, reason=reason, **({"rung": rung} if rung else {}))
            for suite, reason, rung in proving
        ]
    )


def cases() -> list[Case]:
    """(id, record, decision, reason, what it shows)."""
    ok = reader.ACCEPT
    out: list[Case] = [
        (
            "level-0-declared-only",
            build(),
            ok,
            "level=0 next=T1:no_finding",
            "a subject and nothing else: self-declared",
        ),
        (
            "level-1-issuer-marker",
            build(*ladder(1)),
            ok,
            "level=1 next=T2:no_finding",
            "an issuer-signed binding for the subject",
        ),
        (
            "level-1-did-binding",
            build(finding(T1_DID)),
            ok,
            "level=1 next=T2:no_finding",
            "the same level reached through a DID binding",
        ),
        (
            "level-2-marker-survives",
            build(*ladder(2)),
            ok,
            "level=2 next=T3:no_finding",
            "the marker survives every hop",
        ),
        (
            "level-3-holder-bound",
            build(*ladder(3)),
            ok,
            "level=3 next=T4:no_finding",
            "the credential confirms a key and the presenter proved it",
        ),
        (
            "level-4-narrowing-chain",
            build(*ladder(4)),
            ok,
            "level=4 next=T5:no_finding",
            "every delegation only narrows",
        ),
        (
            "level-5-no-unmarked-credential",
            build(*ladder(5)),
            ok,
            "level=5 next=T6:no_finding",
            "the agent can reach no unmarked credential",
        ),
        (
            "level-6-out-of-reach-record",
            build(*ladder(6)),
            ok,
            "level=6 next=none",
            "every test passes; the record sits where the agent cannot reach it",
        ),
        (
            "level-6-e4-anchored",
            build(*ladder(5), finding("vectors-grade-floor/e4-anchored")),
            ok,
            "level=6 next=none",
            "an anchored record clears the floor too",
        ),
        (
            "skips-holder-bound",
            build(*ladder(6, skip=(3,))),
            ok,
            "level=2 next=T3:no_finding",
            "levels 4, 5 and 6 are proven but 3 is not, so the level is 2",
        ),
        (
            "skips-issuer-marker",
            build(*ladder(6, skip=(1,))),
            ok,
            "level=0 next=T1:no_finding",
            "every test above 1 is proven but 1 is not, so the level is 0",
        ),
        (
            "skips-marker-survival",
            build(*ladder(6, skip=(2,))),
            ok,
            "level=1 next=T2:no_finding",
            "the marker is not shown to survive, so the level is 1",
        ),
        (
            "skips-narrowing-chain",
            build(*ladder(6, skip=(4,))),
            ok,
            "level=3 next=T4:no_finding",
            "no chain finding, so the level is 3",
        ),
        (
            "skips-no-unmarked-credential",
            build(*ladder(6, skip=(5,))),
            ok,
            "level=4 next=T5:no_finding",
            "no reachability finding, so the level is 4",
        ),
        (
            "skips-two-levels",
            build(*ladder(6, skip=(3, 5))),
            ok,
            "level=2 next=T3:no_finding",
            "two gaps: the lower one decides",
        ),
        (
            "order-does-not-matter",
            build(*reversed(ladder(6))),
            ok,
            "level=6 next=none",
            "the same findings in reverse order give the same level",
        ),
        (
            "refusal-outvotes-acceptance",
            build(*ladder(3), finding("vectors-holder-bound-credential/proof-signed-by-other-key")),
            ok,
            "level=2 next=T3:finding_refused:proof_key_not_bound",
            "an accepting and a refusing finding for the same test: the refusal stands",
        ),
        (
            "bearer-credential",
            build(*ladder(2), finding("vectors-holder-bound-credential/credential-is-bearer")),
            ok,
            "level=2 next=T3:finding_refused:credential_not_holder_bound",
            "a bearer credential is refused, so no holder binding",
        ),
        (
            "marker-stripped",
            build(finding(T1), finding("vectors-actor-marker-survival/own-marker-stripped")),
            ok,
            "level=1 next=T2:finding_refused:marker_stripped",
            "the marker was stripped at a hop",
        ),
        (
            "issuer-signature-forged",
            build(finding("vectors-principal-binding/uma-signed-by-other-key")),
            ok,
            "level=0 next=T1:finding_refused:signature_invalid",
            "a binding signed by another key proves nothing",
        ),
        (
            "delegation-widened",
            build(*ladder(3), finding("vectors-delegator-right/delegate-scope-exceeds-delegator")),
            ok,
            "level=3 next=T4:finding_refused:delegate_exceeds_delegator",
            "a delegate holding more than its delegator",
        ),
        (
            "subject-mismatch",
            _evidence_swapped(),
            ok,
            "level=2 next=T3:subject_mismatch",
            "a holder-bound finding about another agent does not lift this one",
        ),
        (
            "reachability-exposed",
            build(*ladder(4), finding("vectors-credential-reachability/exposed")),
            ok,
            "level=4 next=T5:reason_not_proving:exposed_verified",
            "a verified exposure is an answer, and not the answer that proves containment",
        ),
        (
            "reachability-credential-signed-by-agent",
            build(*ladder(4), finding("vectors-credential-reachability/signed-by-agent-key")),
            ok,
            "level=4 next=T5:finding_refused:signed_by_agent_key",
            "the probe was signed with a key the agent holds",
        ),
        (
            "floor-below-e2",
            build(*ladder(5), finding("vectors-grade-floor/e1-observed")),
            ok,
            "level=5 next=T6:rung_below_floor:E1",
            "an observed record is below the floor",
        ),
        (
            "floor-rung-missing",
            build(*ladder(5), finding("vectors-grade-floor/e2-enforced", rung=None)),
            ok,
            "level=5 next=T6:rung_missing",
            "an accepting floor finding with no rung",
        ),
        (
            "floor-self-stamped",
            build(*ladder(5), finding("vectors-grade-floor/e0-self-stamped-e4")),
            ok,
            "level=5 next=T6:finding_refused:e1_no_external_observer",
            "a record that stamped itself E4 is refused",
        ),
    ]
    base = build(*ladder(2))
    for name, mutate, reason, shows in _refusals():
        record = copy.deepcopy(base)
        mutate(record)
        out.append((name, record, reader.REJECT, reason, shows))
    return out


def _refusals() -> list[tuple[str, Any, str, str]]:
    def drop(member: str) -> Any:
        return lambda r: r.pop(member)

    def put(member: str, value: Any) -> Any:
        return lambda r: r.__setitem__(member, value)

    def finding_edit(edit: Any) -> Any:
        return lambda r: edit(r["findings"][0])

    return [
        ("contract-id-missing", drop("contractId"), "contract_id_missing", "no contract"),
        ("contract-id-unknown", put("contractId", "x"), "contract_id_unknown", "another contract"),
        ("set-has-extra-member", put("note", "x"), "record_malformed", "a member not in the set"),
        ("subject-empty", put("subject", ""), "record_malformed", "no subject at all"),
        (
            "subject-padded",
            put("subject", " agent:planner"),
            "record_malformed",
            "a subject with surrounding whitespace is not an exact string",
        ),
        ("findings-not-a-list", put("findings", {}), "record_malformed", "findings is an object"),
        (
            "finding-decision-unknown",
            finding_edit(lambda f: f.__setitem__("decision", "maybe")),
            "finding_malformed",
            "a decision other than accept or reject",
        ),
        (
            "finding-digest-short",
            finding_edit(lambda f: f["evidence"].__setitem__("sha256", "abc")),
            "finding_malformed",
            "evidence digest is not 64 hex characters",
        ),
        (
            "finding-digest-uppercase",
            finding_edit(
                lambda f: f["evidence"].__setitem__("sha256", f["evidence"]["sha256"].upper())
            ),
            "finding_malformed",
            "evidence digest is not lowercase hex",
        ),
        (
            "finding-evidence-missing",
            finding_edit(lambda f: f.pop("evidence")),
            "finding_malformed",
            "a finding with no evidence",
        ),
        (
            "finding-rung-unknown",
            finding_edit(lambda f: f.__setitem__("rung", "E9")),
            "finding_malformed",
            "a rung that is not E0 to E4",
        ),
        (
            "finding-subject-padded",
            finding_edit(lambda f: f.__setitem__("subject", "agent:x ")),
            "finding_malformed",
            "a finding subject with trailing whitespace",
        ),
        (
            "finding-extra-member",
            finding_edit(lambda f: f.__setitem__("note", "x")),
            "finding_malformed",
            "a finding member outside the contract",
        ),
        (
            "finding-conflict",
            lambda r: r["findings"].append(dict(r["findings"][0], decision="reject")),
            "finding_conflict",
            "the same evidence reported as accept and as reject",
        ),
        (
            "evidence-claimed-by-two-suites",
            lambda r: r["findings"].append(
                dict(r["findings"][0], suite="holder-bound-credential/v1", reason="holder_bound")
            ),
            "finding_conflict",
            "one digest listed as the proof of two different suites",
        ),
        (
            "evidence-claimed-for-two-subjects",
            lambda r: r["findings"].append(dict(r["findings"][0], subject="agent:other")),
            "finding_conflict",
            "one digest listed as evidence about two different agents",
        ),
        (
            "one-evidence-for-every-level",
            lambda r: r.update(findings=_one_evidence_six_suites()["findings"]),
            "finding_conflict",
            "a single digest listed under all six suites would otherwise grade level 6",
        ),
    ]


def generate(root: Path = ROOT) -> dict[str, Any]:
    """Write every case and the manifest; the reference reader must agree with each case."""
    if (root / "cases").exists():
        shutil.rmtree(root / "cases")
    entries = []
    for name, body, decision, reason, shows in cases():
        directory = root / "cases" / name
        directory.mkdir(parents=True)
        data = _json(body)
        (directory / "record.json").write_bytes(data)
        expected = {"decision": decision, "reason": reason}
        observed = reader.verify(directory / "record.json")
        if observed != expected:
            raise SystemExit(f"{name}: the reader says {observed}, the case {expected}")
        entries.append(
            {
                "edit": shows,
                "expected": expected,
                "files": {"record.json": _sha(data)},
                "id": name,
                "path": f"cases/{name}",
                "retained": reader.retained(body),
            }
        )
    words = [e["expected"]["decision"] for e in entries]
    manifest = {
        "contractId": reader.CONTRACT_ID,
        "corpusDigest": _sha(_json(entries)),
        "counts": {w: words.count(w) for w in sorted(set(words))},
        "reuseSha256": _sha((root / "reuse.json").read_bytes()),
        "sources": SOURCES,
        "suite": SUITE,
        "synthetic": True,
        "verifierContract": "verifier record.json --json; exit 0 accept, 1 reject",
        "vectors": entries,
    }
    (root / "MANIFEST.json").write_bytes(_json(manifest))
    return manifest


def corpus_digest(manifest: dict[str, Any], root: str) -> str:
    """Recompute the corpus digest from the committed case files, not from their declared hashes."""
    base = Path(root)
    entries = []
    for entry in manifest["vectors"]:
        directory = base / entry["path"]
        declared = entry["files"]
        if {path.name for path in directory.iterdir() if path.is_file()} != set(declared):
            raise ValueError(f"{entry['id']}: file set changed")
        files = {name: _sha((directory / name).read_bytes()) for name in declared}
        if files != declared:
            raise ValueError(f"{entry['id']}: file digest mismatch")
        entries.append({**entry, "files": files})
    return _sha(_json(entries))


if __name__ == "__main__":
    generate()
